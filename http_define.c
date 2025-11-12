
#define max_open_files 1024
#define max_client_accepted 500 //
#define thread_pool_num 20 // 151 max conn mariadb connections
#define MAX_CONCURRENT_STREAMS 200
#define dynamic_table_size 1000 // all the chars
#define MAX_HEADER_LIST_SIZE 4096

#define MAX_FRAME_SIZE 16384
#define SETTINGS_INITIAL_WINDOW_SIZE 65535

#define MAXIMUM_WINDOW_UPDATE 1048510465
#define MINIMUM_WINDOW_SIZE 49151
#define max_chunk_size 1000
#define MAX_RECIVE_DATA_SIZE 1048576  //1MB  //81920 = 80ko
#define HEADERS_BTREE_SIZE 2000

#define MAX_EPOLL_EVENTS 20

#define response_writeHead(frm,list) if(H2_res_writeHead(frm,list)==-1){return;}
#define response_write(frm,payload,len) if(H2_res_write(frm->conn,len,0,0,frm->stream_id,payload)==-1){H2_reset_stream(frm->conn, frm->stream_id);return;}
#define response_end(frm,payload,len) H2_res_write(frm->conn,len,0,1,frm->stream_id,payload); H2_res_write(frm->conn, 4, 3, 0, frm->stream_id, "0000"); H2_free_stream(frm->conn, frm->stream_id);

#define free_connection(conn) H2_free_connection(conn); conn=NULL;

#define response_404(frm) response_writeHead(frm, (array{{NULL,13},{NULL,0} })); response_end(frm, "404 Not Found", -1); return;
#define response_500(frm) response_writeHead(frm, (array{{NULL,14},{NULL,0} })); response_end(frm, "500 Internal Server Error", -1); return;

#define open_file(frm,fd,path,modes) if((fd=open(path,modes,0644)) == -1){response_404(frm)}
//~ #define make_dir(frm,path,modes) if(mkdir(path, modes)==-1){response_writeHead(frm, (array{{NULL,14}, {NULL,0} })); response_end(frm, "001 Internal Server Error", 25);return;}

#define response_file(frm,path,headers) open_file(frm, frm->request->file.fd, path, O_RDONLY); response_writeHead(frm,headers);
#define response_end_file(x,y) if(res_file(x, y)==-1){free_req(x);continue;}

#define sql_query(dbconn,data_stack) ((sql_request(dbconn, data_stack))?\
	 ({response_writeHead(frm, (array{{NULL,14}, {NULL,0} })); response_end(frm, "Error in query", -1);return; ((binary_data){NULL,0});}) \
	:({struct buffer data = sql_json_response(dbconn, data_stack); data;}))

//~ #define get_header(frm,header,needle) if(!(header=H2_get_header(frm,needle))){H2_res_writeHead(frm, (array{{NULL,14}}), 1);  response_end(frm->conn, 25, frm->stream_id, "500 Internal Server Error"); }

//~ #define get_header(frm,headers,needle) ({struct H2_header *header = H2_get_header(headers,needle); !header?\
	 //~ ({response_writeHead(frm, (array{{NULL,14}, {NULL,0} })); response_end(frm, "002 Internal Server Error", 25);return; NULL;}): header;})

#define my_account_id(frm,dbconn,data_stack) if(account_id(frm,dbconn,data_stack).len == 0)\
		{response_writeHead(frm, (array{{NULL,14}, {NULL,0} })); response_end(frm, "003 Internal Server Error", 25);return;}

//~ struct epoll_event ev, events[MAX_EPOLL_EVENTS];
int ux_sock, conn_sock, client_accepted, nfds, epollfd, proc_id;

struct H2_connection *conn_list[max_open_files];
struct H2_connection *thread_conn_role;

mtx_t client_accepted_mutex;
//~ mtx_t conn_list_mutex;
mtx_t conn_role_mutex; // unlock one thread to get the thread_conn_role ptr, whene multiple threads waiting on the mutex conn_role_mutex
mtx_t new_conn_mutex; // signal back the main thread whene the thread finish geting the thread_conn_role ptr

#define array (struct buffer[])

#define array_list(list) ((struct buffer[])list)

//~ #define strscmp(x,y,z) strncmp(x, y, z>strlen(x)?strlen(x):z)

SSL_CTX* sslctx;

//~ regex_t jsonMatch;
//~ regex_t doMatch;

//~ #define BC_IF_EVEN(BC)  ( { if(i % 2 == 0) BC; } )

typedef struct bin_tree{
  int num;
  void *ptr;
  struct bin_tree* next[2];
} binary_tree;

typedef struct queue{
	void *ptr;
    void *next;
} data_queue;

typedef struct buffer{
	char *buff;
    int len;
    void *next;
} binary_data;

struct file {
	int fd;
    struct buffer id; // part of fpath
    struct buffer path;
    struct buffer type;
    struct tm time;
    int size;
    int finish;
};

struct H2_header {
	struct buffer name;
	struct buffer value;
    struct H2_header* next;
    struct H2_header* prev;
    int pos;
};

struct H2_Frame {
    int len;
    char type;
    char flags;
    int stream_id;
    //~ void *payload; // use conn->frame_payload instead
    
    struct H2_connection *conn;
    struct H2_request *request;
    
    int dpnd_id;
    unsigned char weight;
    int next_id;
    int prev_id;
    int send_window;
    int recv_window;
};

struct H2_request {
    struct buffer method;
    struct buffer path;
    struct H2_header *headers; // decoded header list
    struct buffer *chunk_struct;
    struct file file;
    void (*application)(struct H2_Frame*);
};

struct H2_connection {
	int fd;
    SSL* ssl;
    mtx_t ready;
	
	struct H2_header *dynamic_table; // headers
	struct H2_header *dyn_table_last;
	int dynamic_table_len;
	
    struct buffer authority; // referenced from dynamic table
    struct buffer cookie; // referenced from dynamic table
    
    struct buffer account_id;
    int event_frm_id;
	
	struct H2_Frame *stream_id[MAX_CONCURRENT_STREAMS];
	unsigned int frm_id;
    //~ int urg_frm;
    //~ int ldr_frm;
    //~ int bck_frm;
    int send_window;
    int recv_window;
    int client_initial_window_size;
    int client_max_frame_size;
    
	struct buffer frame_payload;
	struct buffer headers_reuse; // use headers_reuse to constract headers then send theme // used in H2_res_writeHead func.
    void *ptr;
    
    int events;
    
    //~ struct H2_connection *conn_next;
};

struct request { // old, for http 1.0 only
	//~ struct H2_connection conn;
    struct buffer method;
    struct buffer uri;
    struct buffer query;
    struct buffer version;
    struct buffer cookie;
    struct buffer headers;
    struct buffer remind;
    //~ SSL* ssl;
    struct buffer data;
  };

//~ struct charNode *clients;
//~ struct request *newRequest;

//~ char dateHeaderEND[] = "build-date: " __DATE__ " " __TIME__ " GMT\r\n\r\n";

//~ html text/html
//~ jpg image/jpeg
//~ mp4 video/mp4
//~ png image/png

#define BitVal(data,y)  ((data>>y) & 1)      /** Return Data.Y value  **/
#define SetBit(data,y)    data |= (1 << y)   /** Set Data.Y   to 1    **/
#define ClearBit(data,y)  data &= ~(1 << y)  /** Clear Data.Y to 0    **/
#define TogleBit(data,y) (data ^= BitVal(y)) /** Togle Data.Y  value  **/
#define Togle(data)   	 (data =~data )      /** Togle Data value     **/

 //~ i <<= x;  // i *= 2^x;
 //~ i >>= y;  // i /= 2^y;

struct bin_tree *huff_btree;

const int H2_huff_table[][2] = { // from github.com/nghttp2/nghttp2/blob/master/lib/nghttp2_hd_huffman_data.c
    {13, 0x1ff8u},    {23, 0x7fffd8u},   {28, 0xfffffe2u},  {28, 0xfffffe3u},
    {28, 0xfffffe4u}, {28, 0xfffffe5u},  {28, 0xfffffe6u},  {28, 0xfffffe7u},
    {28, 0xfffffe8u}, {24, 0xffffeau},   {30, 0x3ffffffcu}, {28, 0xfffffe9u},
    {28, 0xfffffeau}, {30, 0x3ffffffdu}, {28, 0xfffffebu},  {28, 0xfffffecu},
    {28, 0xfffffedu}, {28, 0xfffffeeu},  {28, 0xfffffefu},  {28, 0xffffff0u},
    {28, 0xffffff1u}, {28, 0xffffff2u},  {30, 0x3ffffffeu}, {28, 0xffffff3u},
    {28, 0xffffff4u}, {28, 0xffffff5u},  {28, 0xffffff6u},  {28, 0xffffff7u},
    {28, 0xffffff8u}, {28, 0xffffff9u},  {28, 0xffffffau},  {28, 0xffffffbu},
    {6, 0x14u},       {10, 0x3f8u},      {10, 0x3f9u},      {12, 0xffau},
    {13, 0x1ff9u},    {6, 0x15u},        {8, 0xf8u},        {11, 0x7fau},
    {10, 0x3fau},     {10, 0x3fbu},      {8, 0xf9u},        {11, 0x7fbu},
    {8, 0xfau},       {6, 0x16u},        {6, 0x17u},        {6, 0x18u},
    {5, 0x0u},        {5, 0x1u},         {5, 0x2u},         {6, 0x19u},
    {6, 0x1au},       {6, 0x1bu},        {6, 0x1cu},        {6, 0x1du},
    {6, 0x1eu},       {6, 0x1fu},        {7, 0x5cu},        {8, 0xfbu},
    {15, 0x7ffcu},    {6, 0x20u},        {12, 0xffbu},      {10, 0x3fcu},
    {13, 0x1ffau},    {6, 0x21u},        {7, 0x5du},        {7, 0x5eu},
    {7, 0x5fu},       {7, 0x60u},        {7, 0x61u},        {7, 0x62u},
    {7, 0x63u},       {7, 0x64u},        {7, 0x65u},        {7, 0x66u},
    {7, 0x67u},       {7, 0x68u},        {7, 0x69u},        {7, 0x6au},
    {7, 0x6bu},       {7, 0x6cu},        {7, 0x6du},        {7, 0x6eu},
    {7, 0x6fu},       {7, 0x70u},        {7, 0x71u},        {7, 0x72u},
    {8, 0xfcu},       {7, 0x73u},        {8, 0xfdu},        {13, 0x1ffbu},
    {19, 0x7fff0u},   {13, 0x1ffcu},     {14, 0x3ffcu},     {6, 0x22u},
    {15, 0x7ffdu},    {5, 0x3u},         {6, 0x23u},        {5, 0x4u},
    {6, 0x24u},       {5, 0x5u},         {6, 0x25u},        {6, 0x26u},
    {6, 0x27u},       {5, 0x6u},         {7, 0x74u},        {7, 0x75u},
    {6, 0x28u},       {6, 0x29u},        {6, 0x2au},        {5, 0x7u},
    {6, 0x2bu},       {7, 0x76u},        {6, 0x2cu},        {5, 0x8u},
    {5, 0x9u},        {6, 0x2du},        {7, 0x77u},        {7, 0x78u},
    {7, 0x79u},       {7, 0x7au},        {7, 0x7bu},        {15, 0x7ffeu},
    {11, 0x7fcu},     {14, 0x3ffdu},     {13, 0x1ffdu},     {28, 0xffffffcu},
    {20, 0xfffe6u},   {22, 0x3fffd2u},   {20, 0xfffe7u},    {20, 0xfffe8u},
    {22, 0x3fffd3u},  {22, 0x3fffd4u},   {22, 0x3fffd5u},   {23, 0x7fffd9u},
    {22, 0x3fffd6u},  {23, 0x7fffdau},   {23, 0x7fffdbu},   {23, 0x7fffdcu},
    {23, 0x7fffddu},  {23, 0x7fffdeu},   {24, 0xffffebu},   {23, 0x7fffdfu},
    {24, 0xffffecu},  {24, 0xffffedu},   {22, 0x3fffd7u},   {23, 0x7fffe0u},
    {24, 0xffffeeu},  {23, 0x7fffe1u},   {23, 0x7fffe2u},   {23, 0x7fffe3u},
    {23, 0x7fffe4u},  {21, 0x1fffdcu},   {22, 0x3fffd8u},   {23, 0x7fffe5u},
    {22, 0x3fffd9u},  {23, 0x7fffe6u},   {23, 0x7fffe7u},   {24, 0xffffefu},
    {22, 0x3fffdau},  {21, 0x1fffddu},   {20, 0xfffe9u},    {22, 0x3fffdbu},
    {22, 0x3fffdcu},  {23, 0x7fffe8u},   {23, 0x7fffe9u},   {21, 0x1fffdeu},
    {23, 0x7fffeau},  {22, 0x3fffddu},   {22, 0x3fffdeu},   {24, 0xfffff0u},
    {21, 0x1fffdfu},  {22, 0x3fffdfu},   {23, 0x7fffebu},   {23, 0x7fffecu},
    {21, 0x1fffe0u},  {21, 0x1fffe1u},   {22, 0x3fffe0u},   {21, 0x1fffe2u},
    {23, 0x7fffedu},  {22, 0x3fffe1u},   {23, 0x7fffeeu},   {23, 0x7fffefu},
    {20, 0xfffeau},   {22, 0x3fffe2u},   {22, 0x3fffe3u},   {22, 0x3fffe4u},
    {23, 0x7ffff0u},  {22, 0x3fffe5u},   {22, 0x3fffe6u},   {23, 0x7ffff1u},
    {26, 0x3ffffe0u}, {26, 0x3ffffe1u},  {20, 0xfffebu},    {19, 0x7fff1u},
    {22, 0x3fffe7u},  {23, 0x7ffff2u},   {22, 0x3fffe8u},   {25, 0x1ffffecu},
    {26, 0x3ffffe2u}, {26, 0x3ffffe3u},  {26, 0x3ffffe4u},  {27, 0x7ffffdeu},
    {27, 0x7ffffdfu}, {26, 0x3ffffe5u},  {24, 0xfffff1u},   {25, 0x1ffffedu},
    {19, 0x7fff2u},   {21, 0x1fffe3u},   {26, 0x3ffffe6u},  {27, 0x7ffffe0u},
    {27, 0x7ffffe1u}, {26, 0x3ffffe7u},  {27, 0x7ffffe2u},  {24, 0xfffff2u},
    {21, 0x1fffe4u},  {21, 0x1fffe5u},   {26, 0x3ffffe8u},  {26, 0x3ffffe9u},
    {28, 0xffffffdu}, {27, 0x7ffffe3u},  {27, 0x7ffffe4u},  {27, 0x7ffffe5u},
    {20, 0xfffecu},   {24, 0xfffff3u},   {20, 0xfffedu},    {21, 0x1fffe6u},
    {22, 0x3fffe9u},  {21, 0x1fffe7u},   {21, 0x1fffe8u},   {23, 0x7ffff3u},
    {22, 0x3fffeau},  {22, 0x3fffebu},   {25, 0x1ffffeeu},  {25, 0x1ffffefu},
    {24, 0xfffff4u},  {24, 0xfffff5u},   {26, 0x3ffffeau},  {23, 0x7ffff4u},
    {26, 0x3ffffebu}, {27, 0x7ffffe6u},  {26, 0x3ffffecu},  {26, 0x3ffffedu},
    {27, 0x7ffffe7u}, {27, 0x7ffffe8u},  {27, 0x7ffffe9u},  {27, 0x7ffffeau},
    {27, 0x7ffffebu}, {28, 0xffffffeu},  {27, 0x7ffffecu},  {27, 0x7ffffedu},
    {27, 0x7ffffeeu}, {27, 0x7ffffefu},  {27, 0x7fffff0u},  {26, 0x3ffffeeu},
    {30, 0x3fffffffu},
    {0}
};

const char* H2_static_table[][2] = { // from github.com/nghttp2/nghttp2/blob/master/lib/nghttp2_hd.c
	{NULL, NULL},
/*1*/{":authority", NULL},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
/*10*/{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", NULL},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", NULL},
	{"accept-ranges", NULL},
	{"accept", NULL},
/*20*/{"access-control-allow-origin", NULL},
	{"age", NULL},
	{"allow", NULL},
	{"authorization", NULL},
	{"cache-control", NULL},
	{"content-disposition", NULL},
	{"content-encoding", NULL},
	{"content-language", NULL},
	{"content-length", NULL},
	{"content-location", NULL},
/*30*/{"content-range", NULL},
	{"content-type", NULL},
	{"cookie", NULL},
	{"date", NULL},
	{"etag", NULL},
	{"expect", NULL},
	{"expires", NULL},
	{"from", NULL},
	{"host", NULL},
	{"if-match", NULL},
/*40*/{"if-modified-since", NULL},
	{"if-none-match", NULL},
	{"if-range", NULL},
	{"if-unmodified-since", NULL},
	{"last-modified ", NULL},
	{"link", NULL},
	{"location", NULL},
	{"max-forwards", NULL},
	{"proxy-authenticate", NULL},
	{"proxy-authorization", NULL},
/*50*/{"range", NULL},
	{"referer", NULL},
	{"refresh", NULL},
	{"retry-after", NULL},
	{"server", NULL},
	{"set-cookie", NULL},
	{"strict-transport-security", NULL},
	{"transfer-encoding", NULL},
	{"user-agent", NULL},
	{"vary", NULL},
/*60*/{"via", NULL},
	{"www-authenticate", NULL},
};

struct bin_tree *magic_table_btree;

const char* magic_table[][3] = {
	{"application/octet-stream", NULL, NULL}, // default type
	
	{"image/jpeg", "\xFF\xD8\xFF", NULL},
	{"image/png", "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", NULL},
	{"image/gif", "\x47\x49\x46\x38", NULL},
	{"video/mp4", "\x66\x74\x79\x70", "\x04"},
	{"audio/mpeg", "\x49\x44\x33", NULL},
	{"video/ogg", "\x4F\x67\x67\x53", NULL},
	{"image/webp", "\x52\x49\x46\x46", NULL},
	{"video/webm", "\x1A\x45\xDF\xA3", NULL},
	{"video/flv", "\x46\x4C\x56", NULL},
	{"text/utf8", "\xEF\xBB\xBF", NULL},
	{"text/xml", "\x3C\x3F\x78\x6D\x6C\x20", NULL},
	{"application/pdf", "\x25\x50\x44\x46", NULL},
	{"application/zip", "\x50\x4B\x03\x04", NULL},
	{"application/zlib", "\x78", NULL},
	{"application/7zip", "\x37\x7A\xBC\xAF\x27\x1C", NULL},
	{"application/vnd.rar", "\x52\x61\x72\x21\x1A\x07", NULL},
	{"application/msdos", "\x4D\x5A", NULL},
	//~ {"application/iso", "\x43\x44\x30\x30\x31", "\x80\x01"},
	{NULL}
};


const void *headers_path_table[][3];

struct bin_tree *headers_path_table_btree;




char *payload =	"<html>"
				"<head>"
					"<title>my web page</title>"
				"</head>"
				"<body>"
				  "<h1>hello from CH2</h1>"
				  "<h2>an implementation of the Hypertext Transfer Protocol version 2 in C .</h2>"
				"</body>"
				"</html>";




