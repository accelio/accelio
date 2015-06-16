/*
 * Copyright (c) 2013 Mellanox Technologies��. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies�� BSD license
 * below:
 *
 *      - Redistribution and use in source and binary forms, with or without
 *        modification, are permitted provided that the following conditions
 *        are met:
 *
 *      - Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 *      - Neither the name of the Mellanox Technologies�� nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "nbdx.h"


#define cgroup_to_nbdx_session(x) container_of(x, struct nbdx_session, session_cg)
#define cgroup_to_nbdx_device(x) container_of(x, struct nbdx_file, dev_cg)

static ssize_t device_attr_store(struct config_item *item,
			         struct configfs_attribute *attr,
			         const char *page, size_t count)
{
	struct nbdx_session *nbdx_session;
	struct nbdx_file *nbdx_device;
	char xdev_name[MAX_NBDX_DEV_NAME];
	ssize_t ret;

	nbdx_session = cgroup_to_nbdx_session(to_config_group(item->ci_parent));
	nbdx_device = cgroup_to_nbdx_device(to_config_group(item));

	sscanf(page, "%s", xdev_name);
	if(nbdx_file_find(nbdx_session, xdev_name)) {
		pr_err("Device already exists: %s", xdev_name);
		return -EEXIST;
	}

	ret = nbdx_create_device(nbdx_session, xdev_name, nbdx_device);
	if (ret) {
		pr_err("failed to create device %s\n", xdev_name);
		return ret;
	}

	return count;
}

static ssize_t state_attr_show(struct config_item *item,
			       struct configfs_attribute *attr,
			       char *page)
{
	struct nbdx_file *nbdx_device;
	ssize_t ret;

	nbdx_device = cgroup_to_nbdx_device(to_config_group(item));

	ret = snprintf(page, PAGE_SIZE, "%s\n", nbdx_device_state_str(nbdx_device));

	return ret;
}

static struct configfs_item_operations nbdx_device_item_ops = {
		.store_attribute = device_attr_store,
		.show_attribute = state_attr_show,
};

static struct configfs_attribute device_item_attr = {
		.ca_owner       = THIS_MODULE,
		.ca_name        = "device",
		.ca_mode        = S_IWUGO,

};

static struct configfs_attribute state_item_attr = {
		.ca_owner       = THIS_MODULE,
		.ca_name        = "state",
		.ca_mode        = S_IRUGO,

};

static struct configfs_attribute *nbdx_device_item_attrs[] = {
		&device_item_attr,
		&state_item_attr,
		NULL,
};

static struct config_item_type nbdx_device_type = {
		.ct_item_ops    = &nbdx_device_item_ops,
		.ct_attrs       = nbdx_device_item_attrs,
		.ct_owner       = THIS_MODULE,
};

static struct config_group *nbdx_device_make_group(struct config_group *group,
		const char *name)
{
	struct nbdx_session *nbdx_session;
	struct nbdx_file *nbdx_file;

	nbdx_file = kzalloc(sizeof(*nbdx_file), GFP_KERNEL);
	if (!nbdx_file) {
		pr_err("nbdx_file alloc failed\n");
		return NULL;
	}

	spin_lock_init(&nbdx_file->state_lock);
	if (nbdx_set_device_state(nbdx_file, DEVICE_OPENNING)) {
		pr_err("device %s: Illegal state transition %s -> openning\n",
		       nbdx_file->dev_name,
		       nbdx_device_state_str(nbdx_file));
		goto err;
	}

	sscanf(name, "%s", nbdx_file->dev_name);
	nbdx_session = cgroup_to_nbdx_session(group);
	spin_lock(&nbdx_session->devs_lock);
	list_add(&nbdx_file->list, &nbdx_session->devs_list);
	spin_unlock(&nbdx_session->devs_lock);

	config_group_init_type_name(&nbdx_file->dev_cg, name, &nbdx_device_type);

	return &nbdx_file->dev_cg;
err:
	kfree(nbdx_file);
	return NULL;
}

static void nbdx_device_drop(struct config_group *group, struct config_item *item)
{
	struct nbdx_file *nbdx_device;
	struct nbdx_session *nbdx_session;

	nbdx_session = cgroup_to_nbdx_session(group);
	nbdx_device = cgroup_to_nbdx_device(to_config_group(item));
	nbdx_destroy_device(nbdx_session, nbdx_device);
	kfree(nbdx_device);
}

static ssize_t portal_attr_store(struct config_item *citem,
		struct configfs_attribute *attr,
		const char *buf,size_t count)
{
	char rdma[MAX_PORTAL_NAME] = "rdma://" ;
	struct nbdx_session *nbdx_session;

	sscanf(strcat(rdma, buf), "%s", rdma);
	if(nbdx_session_find_by_portal(&g_nbdx_sessions, rdma)) {
		pr_err("Portal already exists: %s", buf);
		return -EEXIST;
	}

	nbdx_session = cgroup_to_nbdx_session(to_config_group(citem));
	if (nbdx_session_create(rdma, nbdx_session)) {
		printk("Couldn't create new session with %s\n", rdma);
		return -EINVAL;
	}

	return count;
}

static struct configfs_group_operations nbdx_session_devices_group_ops = {
		.make_group     = nbdx_device_make_group,
		.drop_item      = nbdx_device_drop,
};

static struct configfs_item_operations nbdx_session_item_ops = {
		.store_attribute = portal_attr_store,
};

static struct configfs_attribute portal_item_attr = {
		.ca_owner       = THIS_MODULE,
		.ca_name        = "portal",
		.ca_mode        = S_IWUGO,

};

static struct configfs_attribute *nbdx_session_item_attrs[] = {
		&portal_item_attr,
		NULL,
};

static struct config_item_type nbdx_session_type = {
		.ct_item_ops    = &nbdx_session_item_ops,
		.ct_attrs       = nbdx_session_item_attrs,
		.ct_group_ops   = &nbdx_session_devices_group_ops,
		.ct_owner       = THIS_MODULE,
};

static struct config_group *nbdx_session_make_group(struct config_group *group,
		const char *name)
{
	struct nbdx_session *nbdx_session;

	nbdx_session = kzalloc(sizeof(*nbdx_session), GFP_KERNEL);
	if (!nbdx_session) {
		pr_err("failed to allocate nbdx session\n");
		return NULL;
	}

	INIT_LIST_HEAD(&nbdx_session->devs_list);
	spin_lock_init(&nbdx_session->devs_lock);
	mutex_lock(&g_lock);
	list_add(&nbdx_session->list, &g_nbdx_sessions);
	created_portals++;
	mutex_unlock(&g_lock);

	config_group_init_type_name(&nbdx_session->session_cg, name, &nbdx_session_type);

	return &nbdx_session->session_cg;

}

static void nbdx_session_drop(struct config_group *group, struct config_item *item)
{
	struct nbdx_session *nbdx_session;

	nbdx_session = cgroup_to_nbdx_session(to_config_group(item));
	nbdx_session_destroy(nbdx_session);
	kfree(nbdx_session);
}

static struct configfs_group_operations nbdx_group_ops = {
		.make_group     = nbdx_session_make_group,
		.drop_item      = nbdx_session_drop,
};

static struct config_item_type nbdx_item = {
		.ct_group_ops   = &nbdx_group_ops,
		.ct_owner       = THIS_MODULE,
};

static struct configfs_subsystem nbdx_subsys = {
		.su_group = {
				.cg_item = {
						.ci_namebuf = "nbdx",
						.ci_type = &nbdx_item,
				},
		},

};

int nbdx_create_configfs_files(void)
{
	int err = 0;

	config_group_init(&nbdx_subsys.su_group);
	mutex_init(&nbdx_subsys.su_mutex);

	err = configfs_register_subsystem(&nbdx_subsys);
	if (err) {
		pr_err("Error %d while registering subsystem %s\n",
				err, nbdx_subsys.su_group.cg_item.ci_namebuf);
	}

	return err;
}

void nbdx_destroy_configfs_files(void)
{
	configfs_unregister_subsystem(&nbdx_subsys);
}
