/*
 * anomaly_fixture.c
 *
 * INTENTIONALLY BUGGY C PROGRAM
 *
 * Purpose:
 *   Static-analysis / anomaly-detection fixture.
 *
 * Contains:
 *   - use-after-free
 *   - double-free
 *   - alias-driven UAF
 *   - stale struct pointers
 *   - dangling stack pointers
 *   - NULL dereferences
 *   - buffer overflows
 *   - off-by-one writes
 *   - integer overflow / truncation
 *   - signed/unsigned confusion
 *   - realloc misuse
 *   - leaks
 *   - double-pointer ownership confusion
 *   - macro side effects
 *   - uninitialized data
 *   - incorrect bounds checks
 *   - loop-dependent bugs
 *   - branch-sensitive bugs
 *   - callback-related lifetime bugs
 *
 * Compile:
 *   gcc -Wall -Wextra -O0 anomaly_fixture.c -o anomaly_fixture
 *
 * DO NOT use as production code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>


/* ============================================================
 *                       WEIRD MACROS
 * ============================================================ */

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*
 * Evaluates x twice.
 * INC_AND_GET(i++) becomes especially nasty.
 */
#define INC_AND_GET(x) ((x) + (++(x)))

#define FREE_AND_NULL(p) \
    do {                 \
        free(p);         \
        (p) = NULL;      \
    } while (0)

/*
 * Looks safe but only clears the local variable passed into it.
 * Aliases remain alive.
 */
#define LOCAL_SAFE_FREE(p) \
    do {                   \
        void *_tmp = (p);  \
        free(_tmp);        \
        (p) = NULL;        \
    } while (0)

/*
 * Arithmetic happens before malloc.
 * Potential overflow.
 */
#define ALLOC_ARRAY(type, count) \
    ((type *)malloc(sizeof(type) * (count)))

#define COPY_IF(dst, src, len, cond) \
    do {                             \
        if (cond)                    \
            memcpy(dst, src, len);   \
    } while (0)


/* ============================================================
 *                       DATA TYPES
 * ============================================================ */

typedef struct Metadata {
    char *name;
    size_t name_len;
    int flags;
} Metadata;


typedef struct Buffer {
    unsigned char *data;
    size_t len;
    size_t capacity;
} Buffer;


typedef struct Node {
    int value;

    struct Node *next;
    struct Node *prev;

    Metadata *meta;

    /*
     * Alias to some externally owned memory.
     * Ownership intentionally unclear.
     */
    char *borrowed_name;

} Node;


typedef struct Session {
    int id;

    Buffer *request;
    Buffer *response;

    Node *owner;

    char *scratch;

    int closed;

} Session;


typedef void (*session_callback)(Session *);


/* ============================================================
 *                 BASIC ALLOCATION HELPERS
 * ============================================================ */

static Buffer *buffer_create(size_t capacity)
{
    Buffer *b = malloc(sizeof(Buffer));

    if (!b)
        return NULL;

    b->data = malloc(capacity);

    if (!b->data) {
        free(b);
        return NULL;
    }

    b->len = 0;
    b->capacity = capacity;

    return b;
}


static void buffer_destroy(Buffer *b)
{
    if (!b)
        return;

    free(b->data);
    free(b);
}


static Metadata *metadata_create(const char *name)
{
    Metadata *m = malloc(sizeof(Metadata));

    if (!m)
        return NULL;

    m->name_len = strlen(name);

    m->name = malloc(m->name_len + 1);

    if (!m->name) {
        free(m);
        return NULL;
    }

    memcpy(m->name, name, m->name_len + 1);

    m->flags = 0;

    return m;
}


static void metadata_destroy(Metadata *m)
{
    if (!m)
        return;

    free(m->name);
    free(m);
}


static Node *node_create(int value, const char *name)
{
    Node *n = malloc(sizeof(Node));

    if (!n)
        return NULL;

    n->value = value;
    n->next = NULL;
    n->prev = NULL;

    n->meta = metadata_create(name);

    /*
     * borrowed_name aliases memory owned by meta.
     */
    n->borrowed_name = n->meta ? n->meta->name : NULL;

    return n;
}


/* ============================================================
 * BUG 1:
 * Hidden alias UAF through nested struct
 * ============================================================ */

static void destroy_metadata_but_keep_alias(Node *node)
{
    if (!node || !node->meta)
        return;

    /*
     * borrowed_name still points to meta->name.
     */
    metadata_destroy(node->meta);

    node->meta = NULL;

    /*
     * node->borrowed_name is now dangling.
     */
}


static void print_borrowed_name(Node *node)
{
    if (!node)
        return;

    if (node->borrowed_name) {
        /*
         * UAF.
         *
         * Path:
         * node->meta->name
         *     ↓ alias
         * node->borrowed_name
         *
         * then metadata_destroy()
         */
        printf("borrowed = %s\n", node->borrowed_name);
    }
}


/* ============================================================
 * BUG 2:
 * Conditional double free
 * ============================================================ */

static void suspicious_cleanup(char *ptr, int mode)
{
    if (!ptr)
        return;

    if (mode > 10) {
        free(ptr);
    }

    if ((mode & 1) == 0) {
        /*
         * Double free when:
         *
         * mode > 10 && mode is even
         */
        free(ptr);
    }
}


/* ============================================================
 * BUG 3:
 * realloc losing original allocation
 * ============================================================ */

static int grow_buffer_bad(Buffer *b, size_t amount)
{
    if (!b)
        return -1;

    size_t new_capacity = b->capacity + amount;

    /*
     * BUG:
     *
     * realloc failure means original pointer is lost.
     */
    b->data = realloc(b->data, new_capacity);

    if (!b->data) {
        b->capacity = 0;
        b->len = 0;

        /*
         * original allocation leaked
         */
        return -1;
    }

    b->capacity = new_capacity;

    return 0;
}


/* ============================================================
 * BUG 4:
 * size_t arithmetic overflow
 * ============================================================ */

static int allocate_packet_array(size_t count)
{
    /*
     * sizeof(uint64_t) * count can overflow.
     */
    uint64_t *packets = ALLOC_ARRAY(uint64_t, count);

    if (!packets)
        return -1;

    for (size_t i = 0; i < count; i++) {
        packets[i] = i;
    }

    free(packets);

    return 0;
}


/* ============================================================
 * BUG 5:
 * Incorrect bounds check + off-by-one
 * ============================================================ */

static int buffer_append_bad(Buffer *b,
                             const unsigned char *src,
                             size_t amount)
{
    if (!b || !src)
        return -1;

    /*
     * BUG:
     *
     * b->len + amount can overflow.
     */
    if (b->len + amount > b->capacity)
        return -1;

    memcpy(b->data + b->len, src, amount);

    b->len += amount;

    /*
     * BUG:
     *
     * If len == capacity this writes one byte OOB.
     */
    b->data[b->len] = '\0';

    return 0;
}


/* ============================================================
 * BUG 6:
 * Signed / unsigned confusion
 * ============================================================ */

static int read_fake_data(Buffer *b, int requested)
{
    if (!b)
        return -1;

    /*
     * intended:
     *   requested <= capacity
     *
     * But requested can be negative.
     */

    if (requested > (int)b->capacity)
        return -1;

    /*
     * requested converted to size_t.
     *
     * -1 -> SIZE_MAX
     */
    memset(b->data, 'A', (size_t)requested);

    b->len = (size_t)requested;

    return 0;
}


/* ============================================================
 * BUG 7:
 * Returning pointer to stack
 * ============================================================ */

static char *make_temporary_name(int id)
{
    char name[32];

    snprintf(name, sizeof(name), "session-%d", id);

    /*
     * BUG: stack address escapes.
     */
    return name;
}


/* ============================================================
 * BUG 8:
 * Double-pointer ownership confusion
 * ============================================================ */

static int replace_string_bad(char **target, const char *replacement)
{
    if (!target)
        return -1;

    char *old = *target;

    free(*target);

    /*
     * target still effectively has old dangling value until
     * successfully replaced.
     */

    if (!replacement)
        return -1;

    char *next = malloc(strlen(replacement) + 1);

    if (!next) {
        /*
         * BUG:
         * caller's *target still points at freed allocation.
         */
        return -1;
    }

    strcpy(next, replacement);

    *target = next;

    /*
     * old is also dangling.
     */
    if (strlen(replacement) == 13) {
        /*
         * Hidden UAF branch.
         */
        printf("old value: %s\n", old);
    }

    return 0;
}


/* ============================================================
 * BUG 9:
 * Aliasing + pointer-to-pointer + conditional destruction
 * ============================================================ */

static void mutate_node(Node **node_ptr, int action)
{
    if (!node_ptr || !*node_ptr)
        return;

    Node *node = *node_ptr;

    Node *alias = node;

    if (action == 1) {
        metadata_destroy(node->meta);
        node->meta = NULL;
    }

    if (action == 2) {

        metadata_destroy(node->meta);

        free(node);

        /*
         * BUG:
         * caller pointer not nulled.
         */

        return;
    }

    if (action > 2) {

        free(node);

        /*
         * alias is dangling here.
         */

        if (action == 42) {
            printf("value=%d\n", alias->value);
        }

        /*
         * caller still holds dangling pointer.
         */
    }
}


/* ============================================================
 * BUG 10:
 * Uninitialized pointer
 * ============================================================ */

static void maybe_initialize(int enable)
{
    char *ptr;

    if (enable) {
        ptr = malloc(32);

        if (ptr)
            strcpy(ptr, "hello");
    }

    /*
     * ptr is uninitialized when enable == 0.
     */
    if (ptr) {
        printf("%s\n", ptr);
        free(ptr);
    }
}


/* ============================================================
 * BUG 11:
 * Loop creates stale pointer after realloc
 * ============================================================ */

static void realloc_loop(Buffer *b)
{
    if (!b)
        return;

    unsigned char *cursor = b->data;

    for (int i = 0; i < 10; i++) {

        if (i == 5) {

            unsigned char *new_data =
                realloc(b->data, b->capacity * 2);

            if (!new_data)
                return;

            b->data = new_data;
            b->capacity *= 2;

            /*
             * cursor still points to old allocation if realloc moved.
             */
        }

        /*
         * potentially UAF after i >= 5.
         */
        cursor[i] = (unsigned char)i;
    }
}


/* ============================================================
 * BUG 12:
 * Nested loops + pointer invalidation
 * ============================================================ */

static void weird_matrix(void)
{
    int **matrix = malloc(5 * sizeof(int *));

    if (!matrix)
        return;

    for (int i = 0; i < 5; i++) {

        matrix[i] = malloc(5 * sizeof(int));

        if (!matrix[i])
            continue;

        for (int j = 0; j <= 5; j++) {
            /*
             * BUG:
             * j <= 5 writes matrix[i][5].
             */
            matrix[i][j] = i * j;
        }
    }

    for (int i = 0; i < 5; i++) {

        if (i == 2 && matrix[i]) {

            free(matrix[i]);

            /*
             * not set to NULL
             */
        }

        if (matrix[i]) {

            /*
             * Double free at i == 2.
             */
            free(matrix[i]);
        }
    }

    free(matrix);
}


/* ============================================================
 * BUG 13:
 * Macro evaluation anomaly
 * ============================================================ */

static void macro_weirdness(void)
{
    int i = 1;

    /*
     * Macro expands roughly into:
     *
     * (i++ + (++i++))
     *
     * Multiple modifications / undefined behavior territory.
     */
    int result = INC_AND_GET(i);

    printf("%d\n", result);
}


/* ============================================================
 * BUG 14:
 * Shallow copy causes ownership duplication
 * ============================================================ */

static Node *clone_node_bad(Node *src)
{
    if (!src)
        return NULL;

    Node *clone = malloc(sizeof(Node));

    if (!clone)
        return NULL;

    /*
     * Shallow copy.
     *
     * clone->meta == src->meta
     * clone->borrowed_name == src->borrowed_name
     */
    memcpy(clone, src, sizeof(Node));

    return clone;
}


static void destroy_node(Node *node)
{
    if (!node)
        return;

    metadata_destroy(node->meta);

    free(node);
}


/* ============================================================
 * BUG 15:
 * Callback observes freed object
 * ============================================================ */

static void debug_session(Session *session)
{
    if (!session)
        return;

    printf("session=%d closed=%d\n",
           session->id,
           session->closed);
}


static void close_session_bad(Session *session,
                              session_callback callback)
{
    if (!session)
        return;

    buffer_destroy(session->request);
    buffer_destroy(session->response);

    free(session->scratch);

    session->closed = 1;

    free(session);

    /*
     * callback receives freed Session.
     */
    if (callback) {
        callback(session);
    }
}


/* ============================================================
 * BUG 16:
 * Pointer escapes object ownership
 * ============================================================ */

static unsigned char *get_internal_buffer(Buffer *buffer)
{
    if (!buffer)
        return NULL;

    /*
     * Borrowed pointer exposed without lifetime information.
     */
    return buffer->data;
}


static void escaped_pointer_example(void)
{
    Buffer *b = buffer_create(32);

    if (!b)
        return;

    unsigned char *external = get_internal_buffer(b);

    buffer_destroy(b);

    /*
     * external is dangling.
     */
    external[0] = 0x41;
}


/* ============================================================
 * BUG 17:
 * Condition appears to protect pointer but doesn't
 * ============================================================ */

static void misleading_guard(Node *node, int trusted)
{
    if (!node)
        return;

    Node *cached = node;

    if (!trusted) {

        free(node);

        node = NULL;
    }

    /*
     * Developer checked node...
     */
    if (node == NULL && cached != NULL) {

        /*
         * ...but cached aliases the allocation that was freed.
         */
        printf("cached=%d\n", cached->value);
    }
}


/* ============================================================
 * BUG 18:
 * Cross-function alias invalidation
 * ============================================================ */

static void invalidate_buffer(Buffer *b)
{
    if (!b)
        return;

    free(b->data);

    /*
     * BUG:
     * b->data remains dangling.
     *
     * len/capacity remain apparently valid.
     */
}


static void cross_function_uaf(void)
{
    Buffer *b = buffer_create(100);

    if (!b)
        return;

    unsigned char *alias1 = b->data;
    unsigned char *alias2 = alias1;

    invalidate_buffer(b);

    if (b->capacity > 50) {

        /*
         * UAF through second-generation alias.
         */
        alias2[20] = 7;
    }

    /*
     * Also double-free because buffer_destroy frees b->data again.
     */
    buffer_destroy(b);
}


/* ============================================================
 * BUG 19:
 * Integer truncation controls allocation
 * ============================================================ */

static void truncation_bug(uint64_t user_size)
{
    /*
     * potentially truncates 64-bit value.
     */
    uint16_t small_size = (uint16_t)user_size;

    char *data = malloc(small_size);

    if (!data)
        return;

    /*
     * copies original user_size rather than small_size.
     */
    memset(data, 'X', user_size);

    free(data);
}


/* ============================================================
 * BUG 20:
 * Arithmetic overflow before bounds check
 * ============================================================ */

static void overflow_before_check(Buffer *b,
                                  size_t offset,
                                  size_t length)
{
    if (!b)
        return;

    /*
     * offset + length may wrap.
     */
    if (offset + length <= b->capacity) {

        /*
         * check may incorrectly pass.
         */
        memset(b->data + offset, 0, length);
    }
}


/* ============================================================
 * BUG 21:
 * Ownership transfer ambiguity
 * ============================================================ */

static void consume_buffer(Buffer *buffer)
{
    buffer_destroy(buffer);
}


static void ownership_confusion(void)
{
    Buffer *b = buffer_create(64);

    if (!b)
        return;

    Buffer *backup = b;

    consume_buffer(b);

    /*
     * Programmer thinks backup is independent.
     */
    if (backup->capacity == 64) {
        backup->data[0] = 1;
    }
}


/* ============================================================
 * BUG 22:
 * linked-list iteration after freeing current node
 * ============================================================ */

static void destroy_list_bad(Node *head)
{
    Node *current = head;

    while (current) {

        destroy_node(current);

        /*
         * BUG:
         * reads current->next after current has been freed.
         */
        current = current->next;
    }
}


/* ============================================================
 * BUG 23:
 * More subtle linked-list mutation problem
 * ============================================================ */

static void remove_even_nodes_bad(Node **head)
{
    if (!head)
        return;

    Node *current = *head;

    while (current) {

        if ((current->value % 2) == 0) {

            Node *victim = current;

            if (current->prev)
                current->prev->next = current->next;
            else
                *head = current->next;

            if (current->next)
                current->next->prev = current->prev;

            free(victim);

            /*
             * BUG:
             * current still equals victim.
             */
        }

        /*
         * UAF when current was even.
         */
        current = current->next;
    }
}


/* ============================================================
 * BUG 24:
 * Pointer arithmetic before validation
 * ============================================================ */

static unsigned char read_offset(Buffer *b, long offset)
{
    if (!b)
        return 0;

    /*
     * Pointer computed before offset validation.
     */
    unsigned char *location = b->data + offset;

    if (offset < 0)
        return 0;

    if ((size_t)offset >= b->len)
        return 0;

    return *location;
}


/* ============================================================
 * BUG 25:
 * NULL field dereference depending on constructor failure
 * ============================================================ */

static void unsafe_node_creation(void)
{
    Node *node = node_create(12, "testing");

    /*
     * Assume node exists.
     */
    node->value++;

    /*
     * Assume metadata allocation succeeded.
     */
    node->meta->flags |= 1;

    destroy_node(node);
}


/* ============================================================
 * BUG 26:
 * Partial initialization + cleanup bug
 * ============================================================ */

static Session *session_create_bad(void)
{
    Session *s = malloc(sizeof(Session));

    if (!s)
        return NULL;

    /*
     * Not zero initialized.
     */

    s->request = buffer_create(64);

    if (!s->request) {
        free(s);
        return NULL;
    }

    s->response = buffer_create(64);

    if (!s->response) {

        buffer_destroy(s->request);

        /*
         * forgot free(s)
         */
        return NULL;
    }

    s->scratch = malloc(128);

    /*
     * owner and closed still uninitialized.
     */

    return s;
}


/* ============================================================
 * BUG 27:
 * Failure path + stale output parameter
 * ============================================================ */

static int create_buffer_out(Buffer **out, size_t size)
{
    if (!out)
        return -1;

    Buffer *b = buffer_create(size);

    if (!b) {
        /*
         * BUG:
         * *out not cleared.
         *
         * Caller could retain stale pointer.
         */
        return -1;
    }

    *out = b;

    return 0;
}


/* ============================================================
 * BUG 28:
 * realloc alias invalidation through struct
 * ============================================================ */

typedef struct Parser {
    Buffer *input;

    unsigned char *cursor;
    unsigned char *token_start;

    size_t position;
} Parser;


static void parser_expand_input(Parser *p)
{
    if (!p || !p->input)
        return;

    /*
     * cursor and token_start point inside input->data.
     */

    unsigned char *new_data =
        realloc(p->input->data,
                p->input->capacity * 4);

    if (!new_data)
        return;

    p->input->data = new_data;
    p->input->capacity *= 4;

    /*
     * BUG:
     * cursor and token_start were not rebased.
     */
}


static void parser_process(Parser *p)
{
    if (!p)
        return;

    for (int round = 0; round < 4; round++) {

        if (round == 2)
            parser_expand_input(p);

        if (p->cursor) {
            /*
             * potentially stale interior pointer
             */
            *p->cursor = (unsigned char)round;

            p->cursor++;
        }
    }
}


/* ============================================================
 * BUG 29:
 * Complex branch-dependent lifetime
 * ============================================================ */

static Node *complex_branch(Node *node,
                            int mode,
                            int retry,
                            int preserve)
{
    if (!node)
        return NULL;

    Node *result = node;
    Node *alias = node;

    if (mode == 1) {

        if (retry > 3) {

            free(node);

            if (preserve) {
                /*
                 * returns dangling pointer
                 */
                return result;
            }

            result = NULL;
        }

    } else if (mode == 2) {

        if (!preserve) {
            destroy_metadata_but_keep_alias(node);
        }

    } else {

        for (int i = 0; i < retry; i++) {

            if (i == 7) {

                free(alias);

                break;
            }
        }

        /*
         * Potential UAF depending on retry.
         */
        if (retry >= 8) {
            result->value++;
        }
    }

    return result;
}


/* ============================================================
 * BUG 30:
 * double indirection + alias chain
 * ============================================================ */

static void indirect_destroy(Node ***triple)
{
    if (!triple || !*triple || !**triple)
        return;

    Node *target = **triple;

    free(target);

    /*
     * Neither **triple nor aliases cleared.
     */
}


static void triple_pointer_example(void)
{
    Node *node = node_create(5, "triple");

    Node *alias = node;

    Node **p1 = &node;
    Node ***p2 = &p1;

    indirect_destroy(p2);

    /*
     * UAF through unrelated alias.
     */
    alias->value = 100;

    /*
     * node itself also remains dangling.
     */
}


/* ============================================================
 * BUG 31:
 * Conditional leak inside complex loop
 * ============================================================ */

static void leak_in_loop(int count)
{
    char **items = calloc((size_t)count, sizeof(char *));

    if (!items)
        return;

    for (int i = 0; i < count; i++) {

        items[i] = malloc(64);

        if (!items[i])
            break;

        snprintf(items[i], 64, "item-%d", i);

        if ((i % 7) == 0) {
            /*
             * pointer forgotten without free
             */
            items[i] = NULL;
        }
    }

    for (int i = 0; i < count; i++) {
        free(items[i]);
    }

    free(items);
}


/* ============================================================
 * BUG 32:
 * Shadowed variable hides ownership error
 * ============================================================ */

static void shadow_bug(void)
{
    char *data = malloc(32);

    if (!data)
        return;

    strcpy(data, "outer");

    {
        char *data = malloc(64);

        if (data) {
            strcpy(data, "inner");
            free(data);
        }
    }

    /*
     * outer data still allocated.
     *
     * Leak.
     */
}


/* ============================================================
 * BUG 33:
 * destination size vs source size confusion
 * ============================================================ */

static void copy_name_bad(Metadata *meta,
                          const char *new_name)
{
    if (!meta || !new_name)
        return;

    size_t incoming = strlen(new_name);

    /*
     * Logic reversed.
     */
    if (incoming >= meta->name_len) {

        /*
         * Existing buffer may be much smaller than incoming string.
         */
        memcpy(meta->name,
               new_name,
               incoming + 1);

        meta->name_len = incoming;
    }
}


/* ============================================================
 * BUG 34:
 * Freed object resurrected from global-like cache
 * ============================================================ */

static Node *cached_node = NULL;


static void cache_node(Node *n)
{
    cached_node = n;
}


static void destroy_cached_owner(Node *n)
{
    free(n);

    /*
     * cached_node not invalidated.
     */
}


static void use_cache(void)
{
    if (cached_node) {
        cached_node->value++;
    }
}


/* ============================================================
 * BUG 35:
 * tricky nested conditional stale alias
 * ============================================================ */

static void nested_alias_bug(Node *node,
                             int a,
                             int b,
                             int c)
{
    if (!node)
        return;

    Node *x = node;
    Node *y = x;
    Node *z = y;

    if (a) {

        if (b) {

            if (!c) {
                free(x);
                x = NULL;
            }

        } else {

            y = NULL;
        }
    }

    /*
     * Only bad when:
     *
     * a == true
     * b == true
     * c == false
     *
     * z aliases freed x.
     */
    if (z && a && b) {
        printf("%d\n", z->value);
    }
}


/* ============================================================
 * MAIN
 *
 * Don't necessarily execute everything.
 * Many routines intentionally invoke undefined behavior.
 * ============================================================ */

int main(int argc, char **argv)
{
    printf("Static analysis anomaly fixture\n");

    /*
     * Keep runtime behavior selectable so compilers don't trivially
     * eliminate every path.
     */
    int selector = argc > 1 ? atoi(argv[1]) : 0;

    if (selector == 1) {

        Node *n = node_create(10, "example");

        destroy_metadata_but_keep_alias(n);

        print_borrowed_name(n);

        free(n);

    } else if (selector == 2) {

        Buffer *b = buffer_create(16);

        unsigned char input[16] = {0};

        buffer_append_bad(b, input, sizeof(input));

        buffer_destroy(b);

    } else if (selector == 3) {

        cross_function_uaf();

    } else if (selector == 4) {

        triple_pointer_example();

    } else if (selector == 5) {

        weird_matrix();

    } else if (selector == 6) {

        escaped_pointer_example();

    } else if (selector == 7) {

        Node *n = node_create(42, "branch");

        n = complex_branch(n, 1, 10, 1);

        /*
         * n may already be dangling.
         */
        if (n)
            printf("%d\n", n->value);

    } else if (selector == 8) {

        Buffer *b = buffer_create(32);

        if (b) {
            realloc_loop(b);
            buffer_destroy(b);
        }

    } else if (selector == 9) {

        Session *s = session_create_bad();

        if (s) {
            s->id = 100;
            close_session_bad(s, debug_session);
        }

    } else if (selector == 10) {

        Node *n = node_create(1, "cached");

        cache_node(n);

        destroy_cached_owner(n);

        use_cache();

    }

    return 0;
}