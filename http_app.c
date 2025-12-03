 
void GET_default(struct H2_Frame *frm) {
	
	response_file(frm, "./files/server/page2.html", (array{{NULL,8}, {"text/html;charset=UTF-8",31},{NULL,0} }));
}

void GET_files(struct H2_Frame *frm) {
	struct H2_connection *conn = frm->conn;
	conn->frame_payload.buff[0] = '.';
	url_safe(conn->frame_payload.buff+1, frm->request->path.buff, frm->request->path.len);
	
	response_file(frm, conn->frame_payload.buff, (array{{"200",8},{NULL,0} })); // ,{"attachment;",25}
}

void GET_favicon(struct H2_Frame *frm) {
	
	response_file(frm, "./files/favicon.ico", (array{{NULL,8}, {"image/icon",31},{NULL,0} }));
}

int upload_file_prepare(struct H2_Frame *frm) {
	
	struct buffer data_save_2;
	struct H2_connection *conn = frm->conn;
	
	H2_req_peek(conn, conn->frame_payload.buff, 20); // peek only 20 byte or less for file magic.
	
	frm->request->file.type = file_magic(frm, ((binary_data){
		conn->frame_payload.buff+BitVal(frm->flags, 3),
		conn->frame_payload.len-BitVal(frm->flags, 3)
	}));
	
	//~ printf("-----------%.*s---\n", frm->request->file.type.len, frm->request->file.type.buff);
	
	frm->request->file.time = date_time();
	//~ 2025-09-24 18:11:08
	
	data_save_2=make_str(conn->frame_payload,
		(array{ {"./files",-1},
			{NULL,frm->request->file.time.tm_year+1900},
			{NULL,frm->request->file.time.tm_mon+1},
			{NULL,frm->request->file.time.tm_mday},
		{NULL,-1} }),
		0777);
		
	random_char((data_save_2.buff+data_save_2.len), 32);
	//~ ./files/2025/9/24/18/A76B45C5D432...

	//~ printf("-----------%.*s---\n", data_save_2.len+32, data_save_2.buff);
	data_save_2.buff[data_save_2.len+32]='\0'; // for the open function
				
	frm->request->file.path.buff = malloc(sizeof(char)*(data_save_2.len+32+1)); // +1 for '\0'
	
	if (!frm->request->file.path.buff)
	{
		return -1;
	}
	
	frm->request->file.path.len = (data_save_2.len+32);
	memcpy(frm->request->file.path.buff, data_save_2.buff, (data_save_2.len+32+1));
	frm->request->file.id.buff = frm->request->file.path.buff+data_save_2.len;
	frm->request->file.id.len = 32;
	
	return 0;
}

void upload_file(struct H2_Frame *frm) {
	
	if (frm->type != 0) { // only data frames
		frm->request->file.fd = -1;
		return;
	}
	
	struct H2_connection *conn = frm->conn;
	
	if (frm->request->file.size == 0)
	{
		if (upload_file_prepare(frm) == -1)
		{
			response_500(frm);
		}
		
		open_file(frm, frm->request->file.fd, conn->frame_payload.buff, O_CREAT|O_WRONLY|O_APPEND);
	}
	
	//~ printf("____%d____\n",  frm->len);
	
	if (H2_req_read(conn, conn->frame_payload.buff, frm->len) == frm->len)
	{
		if ((frm->request->file.size += write(frm->request->file.fd, conn->frame_payload.buff+BitVal(frm->flags, 3), frm->len-(BitVal(frm->flags,3)?cton(conn->frame_payload.buff, 8):0))) <= 0)
		{
			// close(frm->request->fptr);
			// printf("DATA req_stream_fwrite\n");
		}
	}
	else
	{response_500(frm);}
	
	if (BitVal(frm->flags,0)==1) // last frame
	{
		frm->request->file.finish = 1;
		response_writeHead(frm, (array{{"200",8}, {NULL,0} }));
		response_end(frm, frm->request->file.id.buff, frm->request->file.id.len);
	}
	else if (frm->request->file.size > MAX_RECIVE_DATA_SIZE) // file size too big than MAX_RECIVE_DATA_SIZE
	{
		//~ printf("file size too big__________________________________________________________________________________\n");
		frm->request->file.finish = 0;
		response_writeHead(frm, (array{{NULL,14},{NULL,0} }));
		response_end(frm, "file size too big", -1);
		return;
	}
}

//~ method, path, application
const void *headers_path_table[][3] = {
	{"GET", NULL, GET_default}, /*do not remove this, for http2 default req same as "/", you can replace the func GET_default*/
	{"GET", "/", GET_default},
	{"GET", "/files", GET_files},
	{"GET", "/favicon.ico", GET_favicon},
	{"POST", "/upload_file", upload_file},
	{NULL} /*list end*/
};

//~ {"HEAD"},{"DELETE"},{"TRACE"},{"PUT"},{"OPTIONS"},{"TRACE"},{"PATCH"},










