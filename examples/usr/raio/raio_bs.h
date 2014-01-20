#ifndef RAIO_BS_H
#define RAIO_BS_H

#include <sys/queue.h>
#include <stdint.h>

struct raio_io_cmd;
struct raio_bs;

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
typedef int (*raio_completion_cb_t)(struct raio_io_cmd *cmd);


/*---------------------------------------------------------------------------*/
/* forward declarations	                                                     */
/*---------------------------------------------------------------------------*/
struct raio_io_cmd {
	int				fd;
	int				op;
	void				*buf;
	uint64_t			bcount;
	void				*mr;
	uint64_t			fsize;
	int64_t				offset;
	int				is_last_in_batch;
	int				res;
	int				res2;
	int				pad;
	void				*user_context;
	raio_completion_cb_t		comp_cb;

	TAILQ_ENTRY(raio_io_cmd)	raio_list;
};


/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct backingstore_template {
	const char *bs_name;
	size_t bs_datasize;
	int (*bs_open)(struct raio_bs *dev, int fd);
	void (*bs_close)(struct raio_bs *dev);
	int (*bs_init)(struct raio_bs *dev);
	void (*bs_exit)(struct raio_bs *dev);
	int (*bs_cmd_submit)(struct raio_bs *dev, struct raio_io_cmd *cmd);

	SLIST_ENTRY(backingstore_template)   backingstore_siblings;
};

struct raio_bs {
	void				*ctx;
	int				fd;
	int				reserved;
	struct backingstore_template	*bst;
	void				*dd;
};

/*---------------------------------------------------------------------------*/
/* raio_bs_init								     */
/*---------------------------------------------------------------------------*/
struct raio_bs *raio_bs_init(void *ctx, const char *name);

/*---------------------------------------------------------------------------*/
/* raio_bs_exit								     */
/*---------------------------------------------------------------------------*/
void raio_bs_exit(struct raio_bs *dev);

/*---------------------------------------------------------------------------*/
/* raio_bs_open								     */
/*---------------------------------------------------------------------------*/
int raio_bs_open(struct raio_bs *dev, int fd);

/*---------------------------------------------------------------------------*/
/* raio_bs_close							     */
/*---------------------------------------------------------------------------*/
void  raio_bs_close(struct raio_bs *dev);

/*---------------------------------------------------------------------------*/
/* raio_bs_cmd_submit	                                                     */
/*---------------------------------------------------------------------------*/
int raio_bs_cmd_submit(struct raio_bs *dev, struct raio_io_cmd *cmd);

/*---------------------------------------------------------------------------*/
/* register_backingstore_template					     */
/*---------------------------------------------------------------------------*/
int register_backingstore_template(struct backingstore_template *bst);

/*---------------------------------------------------------------------------*/
/* get_backingstore_template	                                             */
/*---------------------------------------------------------------------------*/
struct backingstore_template *get_backingstore_template(const char *name);

#endif  /* #define RAIO_BS_H */
