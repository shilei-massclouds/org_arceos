#include "blk-rq-qos.h"

void __rq_qos_throttle(struct rq_qos *rqos, struct bio *bio)
{
    do {
        if (rqos->ops->throttle)
            rqos->ops->throttle(rqos, bio);
        rqos = rqos->next;
    } while (rqos);
}

void __rq_qos_track(struct rq_qos *rqos, struct request *rq, struct bio *bio)
{
    do {
        if (rqos->ops->track)
            rqos->ops->track(rqos, rq, bio);
        rqos = rqos->next;
    } while (rqos);
}

void __rq_qos_issue(struct rq_qos *rqos, struct request *rq)
{
    do {
        if (rqos->ops->issue)
            rqos->ops->issue(rqos, rq);
        rqos = rqos->next;
    } while (rqos);
}
