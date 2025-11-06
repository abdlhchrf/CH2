# CH2 - HTTP/2 C server

CH2 is an implementation of the Hypertext Transfer Protocol version 2 in C.

* this is http2 only server, no backward compatibility.
* the server is multi threaded.

## Requirements

* c99
* linux 6.15
* openssl OpenSSL 3.6.0


## Example

in file `http_app.c` for server application, write :

```c

char *payload =	"<html>"
		"<head>"
		 "<title>my web page</title>"
		"</head>"
		"<body>"
		 "<h1>hello from CH2</h1>"
		 "<h2>an implementation of the Hypertext Transfer Protocol version 2 in C .</h2>"
		"</body>"
		"</html>";

void my_html(struct H2_Frame *frm) {
	response_writeHead(frm, (array{{"200",8}, {"text/html",31}, {NULL,0} }));
	response_end(frm, payload, -1);
}

```

* `{"200",8}` status 200, 8 is the index of `status 200` in `H2_static_table.c` in file `http_define.c`, same as `{NULL,8}`.
* `{"text/html",31}` `content-type: text/html`, 31 is the index of `content-type` in `H2_static_table.c` .
* in `response_end(frm, payload, -1);` `-1` mean that the function will use `strlen()` to calculate the length of the payload.
> use `-1` in `response_end` only if the buffer `payload` end with `\\0`.


then add the function `my_html` name to `headers_path_table` in file `http_app.c` like this :

```c

const void *headers_path_table[][3] = {
     /* method, path, application */
	{"GET", "/myhtml", my_html},
	{NULL} /*end*/
};

```

* if you use your function name with path '/' you need also to use it with path NULL for http2 default request, like this:

```c

const void *headers_path_table[][3] = {
     /* method, path, application */
	{"GET", NULL, my_html},
	{"GET", "/", my_html},
	{NULL} /*end*/
};

```

in linux terminal do :

* run `make` in terminal.
* run server with `./server`.
* open `https://localhost:8080/` in browser.


## knowledge

* http/2 document rfc9113 <https://httpwg.org/specs/rfc9113.html>.
* HPACK: Header Compression for HTTP/2 rfc7541 <https://httpwg.org/specs/rfc7541.html>.
* HTTP/2 Flow Control - medium <https://medium.com/coderscorner/http-2-flow-control-77e54f7fd518>.
* HTTP/2 101 (Chrome Dev Summit 2015) - youtube <https://www.youtube.com/watch?v=r5oT_2ndjms>.
* c pointers <https://en.wikipedia.org/wiki/Pointer_(computer_programming)>






