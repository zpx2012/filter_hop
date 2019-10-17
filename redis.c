
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <hiredis/hiredis.h>

#include "logging.h"
#include "cache.h"


#define REDIS_SERVER_IP "127.0.0.1"
#define REDIS_SERVER_PORT 6399
#define REIDS_TOKEN "38rh3fF%(!"


static redisContext *ctx;


void build_sync_conn()
{
    if (ctx) {
        redisFree(ctx);
    }
    log_info("Building sync connection with redis server.");

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    do {
        ctx = redisConnectWithTimeout(REDIS_SERVER_IP, REDIS_SERVER_PORT, timeout);
        if (ctx == NULL || ctx->err) {
            if (ctx) {
                //log_error("redisConnectWithTimeout fails: %s", ctx->errstr);
                redisFree(ctx);
            } else {
                //log_error("redisConnectWithTimeout fails: can't allocate redis context");
            }
        }
    }
    while (ctx == NULL || ctx->err);
    log_info("Sync connection built successfully.");
}

int connect_to_redis()
{
    build_sync_conn();

    return 0;
}

int disconnect_from_redis()
{
    if (ctx != NULL) {
        redisFree(ctx);
    }
    return 0;
}

void get_str(const char *key, char *val, size_t len)
{
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "GET %s", key);

    val[0] = 0;
    if (reply == NULL) 
    {
        log_error("get_str fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_NIL) {
        log_debugv("get_str: key not found: %s", key);
    }
    else if (reply->type == REDIS_REPLY_STRING) {
        strncat(val, reply->str, len);
        log_debugv("get_str: %s %s", key, val);
    }
    else {
        log_warn("get_str: unexpected reply type: %d", reply->type);
    }
    
    freeReplyObject(reply);
}

int get_int(const char *key)
{
    int val = 0;

    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "GET %s", key);
    if (reply == NULL) 
    {
        log_error("get_int fails: %s", ctx->errstr);
        // handle error
        return 0;
    }
    if (reply->type == REDIS_REPLY_NIL) {
        val = 0;
        log_debugv("get_int: key not found: %s", key);
    }
    else if (reply->type == REDIS_REPLY_INTEGER) {
        val = reply->integer;
        log_debugv("get_int: %s %d", key, val);
    }
    else if (reply->type == REDIS_REPLY_STRING) {
        val = strtol(reply->str, NULL, 10);
        log_debugv("get_int: %s %d", key, val);
    }
    else {
        log_warn("get_int: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
    return val;
}

void set_str(const char *key, const char *val)
{
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "SET %s %s", key, val);
    if (reply == NULL)
    {
        log_error("set_str fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_str %s %s %s", key, val, reply->str);
    }
    else {
        log_warn("set_str: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_int(const char *key, int val)
{
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "SET %s %d", key, val);
    if (reply == NULL)
    {
        log_error("set_int fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_int %s %d %s", key, val, reply->str);
    }
    else {
        log_warn("set_int: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_str_ex(const char *key, const char *val, int timeout)
{
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "SETEX %s %d %s", key, timeout, val);
    if (reply == NULL)
    {
        log_error("set_str_ex fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_str_ex %s %s %s", key, val, reply->str);
    }
    else {
        log_warn("set_str_ex: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_int_ex(const char *key, int val, int timeout)
{
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "SETEX %s %d %d", key, timeout, val);
    if (reply == NULL)
    {
        log_error("set_int_ex fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_int_ex %s %d %s", key, val, reply->str);
    }
    else {
        log_warn("set_int_ex: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_str_ex_nx(const char *key, const char *val, int timeout)
{
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "SET %s %s EX %d NX", key, val, timeout);
    if (reply == NULL)
    {
        log_error("set_str_ex_nx fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_str_ex_nx %s %d %s", key, val, reply->str);
    }
    else if (reply->type == REDIS_REPLY_NIL) {
        log_debugv("set_str_ex_nx: %s exists", key);
    }
    else {
        log_warn("set_str_ex_nx: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_int_ex_nx(const char *key, int val, int timeout)
{
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "SET %s %d EX %d NX", key, val, timeout);
    if (reply == NULL)
    {
        log_error("set_int_ex_nx fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_int_ex_nx %s %d %s", key, val, reply->str);
    }
    else if (reply->type == REDIS_REPLY_NIL) {
        log_debugv("set_int_ex_nx: %s exists", key);
    }
    else {
        log_warn("set_int_ex_nx: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

int incr(const char *key)
{
    int val = 0;

    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "INCR %s", key);
    if (reply == NULL)
    {
        log_error("incr fails: %s", ctx->errstr);
        // handle error
        return 0;
    }
    if (reply->type == REDIS_REPLY_INTEGER) {
        val = reply->integer;
        log_debugv("incr %s %d", key, val);
    }
    else {
        log_warn("incr: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
    return val;
}

void expire(const char *key, int timeout)
{
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "EXPIRE %s %d", key, timeout);
    if (reply == NULL)
    {
        log_error("expire fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_INTEGER) {
        log_debugv("expire: %s %d", key, reply->integer);
    }
    else {
        log_warn("expire: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void keys(const char *pattern)
{
    int i;
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "KEYS %s", pattern);
    if (reply == NULL)
    {
        log_error("keys fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_ARRAY) {
        for (i = 0; i < reply->elements; i++) {
            log_debugv("%d) %s", i, reply->element[i]->str);
        }
    }
    else {
        log_warn("keys: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void del_key(const char *key)
{
    int i;
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "DEL %s", key);
    if (reply == NULL)
    {
        log_error("del_key fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_INTEGER) {
        log_debugv("del_key: %s %d", key, reply->integer);
    }
    else {
        log_warn("del_key: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void flushall()
{
    redisReply *reply;
    reply = (redisReply*)redisCommand(ctx, "FLUSHALL");
    if (reply == NULL)
    {
        log_error("flushall fails: %s", ctx->errstr);
        // handle error
        return;
    }
    freeReplyObject(reply);
}


