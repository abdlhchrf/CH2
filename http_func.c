
 
		
//~ void sighand(int n) {
	//~ printf("sighand recive \n");
//~ }


int init_regex() {
	//~ regcomp(&jsonMatch, "^\\{(\"(H|M|P|T|F)\":\\[(\\[((\"[^\"\\']{0,}\"|[0-9]{1,2})(\\,|\\])){1,}(\\]|\\,)){1,}(\\}|\\,)){1,}\n$", REG_EXTENDED);
	//~ regcomp(&doMatch, "^\\?(do=(file|pst|updtpst|drppst|pnt|upvt|rmvvt|dwnvt|avtr|uncntct|cntct|blk|newnm|subtxt|msg)(|&id=[a-zA-Z0-9\\-\\_]{0,}))\n$", REG_EXTENDED);
	//~ "/^\{(\"(H|M|P|T|F)\":\[(\[((\"[^\"\']{0,500}\"|[0-9]{1,2})(\,|\])){1,4}(\]|\,)){1,50}(\}|\,)){1,5}\n$/"
	 //~ "^\{(\"(H|M|P|T|F)\":\[(\[((\"[^\"\']{0,500}\"|[0-9]{1,2})(\,|\])){1,4}(\]|\,)){1,50}(\}|\,)){1,5}\n$"
	return 1;
}

long int stol(const char *str)
{
    long int res = 0;
    char c,v;
    
    while ((c = *str++)) {
        v = ((c & 0xF) + (c >> 6)) | ((c >> 3) & 0x8);
        res = (res << 4) | (long int) v;
    }
    
    return res;
}

long int xtol(struct buffer path) // hex to long, from stackoverflow
{
    long int res = 0;
    char c,v;
    
    while (path.len>0) {
		c = *path.buff++;
        v = ((c & 0xF) + (c >> 6)) | ((c >> 3) & 0x8);
        //~ printf("__%b__%b__%b__%b_\n", v, c, ((c & 0xF) + (c >> 6)), ((c >> 3) & 0x8));
        res = (res << 4) | (long int) v;
        path.len--;
    }
    
    return res;
}

void ltox(char **str, long int num) // long to hex
{
    char hexstr[] = "0123456789ABCDEF";
    char c;
    
    for (int i = 0; i < sizeof(long int); i++)
	{
		c=(num&(0xff<<i))>>i;
		(*str)[0]=hexstr[(c&0x0f)];
		(*str)++;
		(*str)[0]=hexstr[(c&0xf0)>>4];
		(*str)++;
	}
	(*str)[0]='\0';
}

long int add_up(char *str, int len) {
	long int i=0;
	//~ printf("__tttt___%ld___\n", sizeof(long int));
	while (len>0)
	{
		i+=str[0];
		str++;
		len--;
	}
	return i;
}

char* random_char(char *str, int len)
{
    long int i=0;
    char charstr[] = "0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"; // __lenght____64___
    unsigned char buf[len];
	char *pos=str;
	while (i==0) {
		RAND_bytes(buf, len);
		i=add_up((char*)buf, len);
	}
	
	for (i = 0; i < len; i++)
	{
		if (((buf[i]&0xC0)>>6)+(buf[i]&0x3F) < 64)
		{
			str[0]=charstr[((buf[i]&0xC0)>>6)+(buf[i]&0x3F)];
		}
		else
		{
			str[0]=charstr[(buf[i]&0x3F)]; // this one can work 
		}
		
		str++;
	}
    
    return pos;
}

char* random_hex(char *str, int len)
{
    long int i=0;
    char hexstr[] = "0123456789ABCDEF"; // __lenght____16___
    unsigned char buf[len>>1];
	char *pos=str;
	while (i==0) {
		RAND_bytes(buf, len>>1);
		i=add_up((char*)buf, len>>1);
	}
	
	for (i = 0; i < len>>1; i++)
	{
		str[0]=hexstr[(buf[i]&0x0f)];
		str++;
		str[0]=hexstr[(buf[i]&0xf0)>>4];
		str++;
	}
    
    return pos;
}

int ston(struct buffer data)
{
	int i=0;
	while (data.len>0)
	{
		i=(i<<3)+(i<<1);
		i+=data.buff[0]&0xF;
		data.buff++;
		data.len--;
	}
	
	return i;
}

int cton(const char *str, int size) // bits to number
{
    //~ int mask = 0xffffffff>>((sizeof(int)<<3)-((size%8)==0?8:(size%8)));
	int mask = size>=(sizeof(int)<<3)?-1:((1 << size)-1);
    int res = 0;
    
    if (size>32)
	{
		return -1;
	}
	
	while (size>0)
	{
		size-=8;
		res<<=8;
		res|=str[0]&0xFF;
		//~ printf("_____%x___\n\n", res);
		str++;
	}
	
	res&=mask;
	
    return res;
}

char *ntoc(char *str, int num, int size) // represent number in bits
{
	//~ int size = sizeof(int);
	//~ size <<= 3;
	//~ int mask = 0xff<<size;
	//~ int res = 0;
	int i=0,k=0,f=0;
    char *end = str;
    end[0] = 0;
	// 11111111 00000000 00000000 00000000
	// 00000000 11111111 00000000 00000000
	// 00000000 00000000 11111111 00000000
	// 00000000 00000000 00000000 11111111
	
	if (size>32)
	{
		return NULL;
	}
	
	//~ a[3] = (num>>24) & 0xFF;
	//~ a[2] = (num>>16) & 0xFF;
	//~ a[1] = (num>>8) & 0xFF;
	//~ a[0] = num & 0xFF;
	
    while (1)
	{
		//~ printf("\n---___%02x____%d__%d__\n\n", (unsigned char)end[0], num, size);
		
		i+=8;
		
		if (i<size)
		{
			end[0]=((num>>(i-8))&0xff);
		}
		else if (i==(size+8))
		{
			break;
		}
		else
		{
			end[0]=((num>>(i-8))&((1<<(8-(i-size)))-1));
			break;
		}
		
		for (f=k; f>=0; f--)
		{
			end[f+1] = end[f];
		}
		
		k++;
	}
	
	//~ for (f = 0; f < k+1; f++) {
		//~ printf("_%02x", (unsigned)(end)[f] & 0xFF);
	//~ }
	
	//~ printf("\n\n");
	
    //~ while (size>0)
	//~ {
		//~ size-=8;
		//~ end[0]=(size>=0?
			//~ ((num>>size)&0xff):
			//~ num&((1 << (0-size))-1)
		//~ ); //masking
		//~ printf("---___%02x____%d____\n\n", (unsigned char)end[0], size);
		//~ end++;
	//~ }
	
    return str;
}

long strnum(char *buffer, int size) { // convert number in string to number long
    long i, result = 0;
    
	for (i = 0; i < size; i++) {
		if (!(buffer[i] >= '0' && buffer[i] <= '9'))
		{
			return -1;
		}
		result = result * 10 + (buffer[i] - '0');
	}
	
    //~ printf("parseNumber __%s___ %d____ %ld___\n",buffer, size, result);
	
    return result;
}

struct buffer numstr(struct buffer buff, int pos, long numb) { // convert number to string  Ex: 1234 ==> "1234"
	struct buffer data_save = buff;
	long k=0;
	int a=0, i=0, h=0;
	char data[30];
	
	//~ printf("__%ld__---\n", numb);
	
	k = numb;
	if (k==0)
	{
		buff.buff[pos] = '0';
		a++;
	}
	else
	{
		while (a<=buff.len)
		{
			//~ if (k&0x0F <= 0x9)
			//~ {}
			
			h = k % 10;
			k = k / 10;
			data[a] = (h|0x30);
			a++;
			
			if (k==0) {break;}
		}
		
		for (h=0,i=a-1; i >= 0 && pos<buff.len-2; i--,h++)
		{
			buff.buff[pos] = data[i];
			pos++;
			//~ printf("___________%*.s_____%c____%d____%d\n", a, buff.buff, data[h], h, i);
		}
			//~ printf("_________%s_____%c____%d____%d\n", buff.buff, data[h], h, i);
	}
	
	//~ buff.buff[pos] = '\0';
	data_save.len = a;
	return data_save;
}

long get_file_size(FILE* file) {
  //~ FILE* file = fopen(filename, "rb");
  //~ fseek(file, 0, SEEK_END);
  long size = ftell(file);
  //~ fclose(file);
  return size;
}

int req_stream(struct request *req) { // not used
	FILE *fptr;
	char chunk[10000];
	//~ int chunkSize=0;
	int t = 0;
	long i;
	long size=0;
	//~ random();
	if ((i = 1) == -1) {
		printf("req_stream_get_header\n");
		return -1;
	}
	
	//~ printf("%s---%ld---\n", chunk, i);
	i = strnum(chunk, i);
	if (i == -1) {
		printf("req_stream_parseNumber\n");
		return -1;
	}
	
	//~ if ((i = get_header(req, chunk, "Content-Name: ")) == -1)
	//~ {
		//~ printf("req_stream_get_header\n");
		//~ return -1;
	//~ }
	
	fptr = fopen("./Files/filename", "ab");
	
	if (fptr == NULL) {
		//~ fclose(fptr);
		printf("req_stream_fptr\n");
		return -1;
	}
	
	if (req->remind.buff) { // POST request
		size = req->remind.len;
		if (fwrite(req->remind.buff, sizeof(char), req->remind.len, fptr)<=0)
		{
			fclose(fptr);
			printf("remind_req_stream_fwrite\n");
			return -1;
		}
	}
	
	// req_stream(req);
	//~ while ((chunkSize = req_read(req, chunk, 10000)) != -1) {
		//~ size+=chunkSize;
		//~ // Append some text to the file
		//~ if (fwrite(chunk, sizeof(char), chunkSize, fptr)<=0)
		//~ {
			//~ fclose(fptr);
			//~ printf("req_stream_fwrite\n");
			//~ return -1;
		//~ }
		
		//~ // printf("-----req_stream ------ %ld------ %ld\n", size, i);
		//~ if (size > 1000000000 || size == i) {
			//~ break;
		//~ }
	//~ }
	
	fclose(fptr);
	
	//~ printf("-----size req_stream------ %ld %ld\n", size, i);
	if (size != i) {return -1;}
	
	return t;
}

//~ int res_file(struct H2_Frame *frm, FILE *fptr) {
	//~ // FILE *fptr;
	//~ char chunk[1000];
	//~ int size;
	//~ int t = 0;
	
	//~ while((size=fread(chunk, sizeof(char), 1000, fptr)) && t != -1) {
		//~ t = res_write(frm, chunk, size);
		//~ // printf("%d\t\n",size);
	//~ }
	
	//~ fclose(fptr);
	//~ return t;
//~ }

//~ int res_end(struct H2_Frame *frm, char *buffer, int size) {
	//~ int t = res_write(frm, buffer, size);
	//~ free_req(frm);
	//~ return t;
//~ }

//~ int res_endHead(struct request *req, char *buffer) {
	//~ return res_write(req, dateHeader);
//~ }

//~ int H2_get_frame(struct H2_connection *conn, int i, int dpnd) {
	//~ for (; i <= MAX_CONCURRENT_STREAMS; i++)
	//~ {
		//~ if (conn->stream_id[i] && conn->stream_id[i]->dpnd_id == dpnd)
		//~ {
			//~ return i;
		//~ }
	//~ }
	//~ return -1;
//~ }

//~ void H2_free_req(struct H2_connection *conn) {
//~ }

int strscmp(char *needle, char *data, int len) {
	
	if (len==0){return -1;}
	
	while (len>0 && *needle!='\0')
	{
		if (*needle!=*data) {return -1;}
		needle++;
		data++;
		len--;
	}
	
	return 0;
}

struct buffer make_str(struct buffer data_stack, struct buffer list[], int dir_mode) {
	int i=0, j=0, k=0;
	
	while (list[i].buff || list[i].len>-1)
	{
		//~ printf("-------%s---\n", list[i].buff);
		
		if (list[i].buff)
		{
			j = list[i].len>-1?list[i].len:strlen(list[i].buff);
			memcpy(data_stack.buff+k, list[i].buff, j);
			k+=j;
		}
		else if (k+10<data_stack.len)
		{
			//~ 2025-09-24 18:11:08 example
			k += numstr(data_stack, k, list[i].len).len;
		}
		
		i++;
		
		if (dir_mode>0)
		{
			data_stack.buff[k]='\0';
			
			if (mkdir(data_stack.buff, dir_mode)==-1)
			{
				//~ printf("-----make dir error---\n");
			}
			
			data_stack.buff[k]='/';
			k++;
		}
	}
	
	data_stack.buff[k]='\0';
	
	return ((binary_data){data_stack.buff, k});
}

void str_rmv_char(char c, struct buffer path) {
	for (int i = 0; i < path.len; i++)
	{
		if (path.buff[i]==c)
		{
			path.buff[i]=' ';
		}
	}
}

int strpos(char *needle, struct buffer data) {
	
// X X X X A A A A A B O
		// A A A B O 
		
	int i=0;
	int j=0;
	//~ int h=strlen(needle);
	for (i=0; i < data.len && needle[j]!='\0'; i++)
	{
		//~ printf("___%d___%d___\n", j, i);
		if (needle[j]==data.buff[i])
		{
			j++;
			if (needle[j]=='\0')
			{
				return i;
			}
		}
		else
		{
			i-=j;
			j=0;
		}
	}
	return -1;
}

int url_safe(char *to, char *data, int size) { // url_safe to prevent ../../ ... atack
	char *end = to;
	int i = 0;
	int k = 0;
	for (i = 0; i < size; i++)
	{
		k++;
		//~ printf("%c\n", data[i]);
		switch (data[i])
		{
			case '/':
				if (i+3 < size)
				{
					if (data[i+1] == '.' && data[i+2] == '.' && data[i+3] == '/')
					{
						i+=2;
						break;
					}
				}
			default:
				end[0] = (data+i)[0];
				end++;
			break;
		}
	}
	
	end[0] = '\0';
	
	return k;
}

int str_escape(struct buffer str, int *pos, struct buffer data) {
	
	int j = data.len>=0?data.len:strlen(data.buff);
	for (int i = 0; i<j && (*pos)<str.len-2; i++)
	{
		//~ printf("%c\n", data.buff[i]);
		switch (data.buff[i])
		{
			case '\'':
				strcpy(str.buff+(*pos), "\\'"); (*pos)+=2;
				break;
			case '\"':
				strcpy(str.buff+(*pos), "\\\""); (*pos)+=2;
				break;
			case '\0':
				strcpy(str.buff+(*pos), "\\0"); (*pos)+=2;
				break;
			case '\\':
				strcpy(str.buff+(*pos), "\\\\"); (*pos)+=2;
				break;
			case '\n':
				strcpy(str.buff+(*pos), "\\n"); (*pos)+=2;
				break;
			case '\r':
				strcpy(str.buff+(*pos), "\\r"); (*pos)+=2;
				break;
			case '\t':
				strcpy(str.buff+(*pos), "\\t"); (*pos)+=2;
				break;
			case '\b':
				strcpy(str.buff+(*pos), "\\b"); (*pos)+=2;
				break;
			case '\v':
				strcpy(str.buff+(*pos), "\\v"); (*pos)+=2;
				break;
			case '\e':
				strcpy(str.buff+(*pos), "\\e"); (*pos)+=2;
				break;
			case '\f':
				strcpy(str.buff+(*pos), "\\f"); (*pos)+=2;
				break;
			//~ case '\u':
				//~ strcpy(str.buff+(*pos), "\\u"); (*pos)+=2;
				//~ break;
			default:
				str.buff[(*pos)] = data.buff[i];
				(*pos)++;
				break;
		}
	}
	str.buff[(*pos)] = '\0';
	return (*pos);
}

int str_pack(struct buffer path) { // left shift chars to remove void
	
	int i=0,j=-1;
	
	for (i=0; i < path.len; i++)
	{
		if (j>-1 && path.buff[i] != 0)
		{
			path.buff[j] = path.buff[i];
			path.buff[i] = 0;
			j++;
		}
		else if (j==-1 && path.buff[i] == 0)
		{
			j=i;
		}
	}
		
	return j;
}

int str_hex_ch(struct buffer path, char prefix) {
	
	//~ struct buffer data = ((binary_data){NULL,0});
	int i=0;
	char c=0;
	
	for (i = 0; i < path.len-2; i++) // 2 for the last two hex integer
	{
		if (path.buff[i] == prefix)
		{
			path.buff[i]=0;
			
			c = path.buff[i+2];
			path.buff[i] = ((c & 0xF) + (c >> 6)) | ((c >> 3) & 0x8);
			
			c = path.buff[i+1];
			path.buff[i] |= (((c & 0xF) + (c >> 6)) | ((c >> 3) & 0x8)) << 4;
			
			//~ printf("___%x___\n", path.buff[i]);
			
			path.buff[i+1]=0;
			path.buff[i+2]=0;
			
			i+=2;
		}
	}
	
	if (c!=0)
	{
		return str_pack(path);
	}
	
	return path.len;
}

//~ ?title=mystring&action=testedit
struct buffer querystring(char *needle, struct buffer path) {

	struct buffer data_save = ((binary_data){NULL,-1});
	int i=-1, j=-1;
	
	path.len = str_hex_ch(path, '%');
	
	//~ printf("___%d___\n",path.len);
	
	i=strpos("?", path)+1;
	i+=strpos(needle, ((binary_data){path.buff+i, path.len-i}))+1;
	
	if (i>0 && path.len>i && path.buff[i]=='=')
	{
		i++;
		j=strpos("&", ((binary_data){path.buff+i,path.len-i}));

		if (j>-1)
		{
			data_save.buff = path.buff+i;
			data_save.len = j;
		}
		else
		{
			data_save.buff = path.buff+i;
			data_save.len = path.len-i;
		}
	}
	
	//~ printf("-----------%.*s---\n", data_save.len, data_save.buff);
	
	//~ str_rmv_ch('+', data_save);
	
	//~ +bic+s +
	
	for (i = 0; i < data_save.len; i++)
	{
		switch (data_save.buff[i])
		{
			case '+': case '*': case '-': case '"':case'@':
			case '<': case '>': case '(': case ')': case '~':
				switch (data_save.buff[i-1])
				{
					case '+': case ' ': case '-': case '"':case'@':
					case '<': case '>': case '(': case ')': case '~':
					data_save.buff[i-1]=' ';
					if (data_save.buff[i]=='*')
					{
						data_save.buff[i]=' ';
					}
					break;
					default:
					break;
				}
				
				if (i==data_save.len-1 && (data_save.buff[i]!='*'))
				{
					data_save.buff[i]=' ';
				}
			break;
			default:
			break;
		}
	}
	
	return data_save;
}

struct buffer json_get(char *path, struct buffer *data) {
	/*
		not working with numbers null and true false yet
	*/
	int i=0, j=0, pos=0, depth=0, target=0, key=0, key_pos=0;
	char jsn_spr[10];
	struct buffer data_save = ((binary_data){NULL,-1});
	
	if (!data) {return data_save;}
	
	while (i < data->len)
	{
		//~ printf("___i_%d___j_%d___pos_%d___target_%d___depth_%d___key_%d____-%c-____%c--%c_\n\n", i, j, pos, target, depth, key, jsn_spr[depth], data->buff[i], path[j]);
		//~ printf("_%s___\n", data->buff+i);
		
		switch (path[j])
		{
			case '[':
				if (data->buff[i]!='[') {break;}
				key=0;
				pos=0;
				j++;
				while (path[j]!=']' && path[j]!='\0')
				{
					pos=(pos<<3)+(pos<<1);
					pos+=path[j]&0xF;
					j++;
				}
				if (pos==0) {j++;}
				target=depth+1;
				break;
			case ']':
				if (pos==0) {j++;}
				//~ target=depth;
				break;
			case '\0':
				if (target==0) {target++;}
				break;
			case '.':
				j++;
				key_pos=j;
				target=depth;
				break;
			default:
				if (data->buff[i]=='"') {j=key_pos;}
		}
		
		// *************************************************************************************************************
		 
		switch (data->buff[i])
		{
			case '{':
				key=1;
			case '[':
				if (depth==target && pos==0)
				{
					data_save.buff = data->buff+i;
				}
				depth++;
				jsn_spr[depth]=data->buff[i];
				break;
			case '}':
				key=0;
			case ']':
				if (jsn_spr[depth] == (data->buff[i]-2))
				{
					depth--;
					if (depth==target && depth>0)
					{
						if (pos==0)
						{
							data_save.len = (data->buff+i)-data_save.buff+1;
							i = data->len;
						}
						else
						{
							pos--;
						}
					}
				}
				break;
			case '"':
				if (jsn_spr[depth]==data->buff[i])
				{
					//~ printf("___%d___\n",pos);
					depth--;
					if (depth==target && key!=1)
					{
						if (pos==0)
						{
							data_save.len = (data->buff+i)-data_save.buff;
							i = data->len;
						}
						else
						{
							pos--;
						}
					}
					if (key==1) {key=0;}
				}
				else
				{
					if (path[j]=='['){i = data->len;}
					if (depth==target && key!=1 && pos==0)
					{
						data_save.buff = data->buff+i+1;
					}
					depth++;
					jsn_spr[depth]=data->buff[i];
				}
				break;
			case '\\':
				i++;
				break;
			case ':':
				if (jsn_spr[depth]=='{') {key=0; break;}
			case ',':
				if (jsn_spr[depth]=='{') {key=1; break;}
			default:
				if (key==1)
				{
					if (path[j]==data->buff[i])
					{
						j++;
					}
					else
					{
						j=key_pos;
					}
				}
				break;
		}
		
		i++;
	}
	
	//~ printf("\njson: %.*s\n", data->len, data->buff);
	//~ printf("path: %s \n", path);
	//~ printf("%d__rsult: %.*s\n\n", data_save.len, data_save.len, data_save.buff);
	return data_save;
}

struct tm date_time()
{
	//~ struct tm
	//~ {
	  //~ int tm_sec;			/* Seconds.	[0-60] (1 leap second) */
	  //~ int tm_min;			/* Minutes.	[0-59] */
	  //~ int tm_hour;			/* Hours.	[0-23] */
	  //~ int tm_mday;			/* Day.		[1-31] */
	  //~ int tm_mon;			/* Month.	[0-11] */
	  //~ int tm_year;			/* Year	- 1900.  */
	  //~ int tm_wday;			/* Day of week.	[0-6] */
	  //~ int tm_yday;			/* Days in year.[0-365]	*/
	  //~ int tm_isdst;			/* DST.		[-1/0/1]*/
	  
	//~ # ifdef	__USE_MISC
	  //~ long int tm_gmtoff;		/* Seconds east of UTC.  */
	  //~ const char *tm_zone;		/* Timezone abbreviation.  */
	//~ # else
	  //~ long int __tm_gmtoff;		/* Seconds east of UTC.  */
	  //~ const char *__tm_zone;	/* Timezone abbreviation.  */
	//~ # endif
	//~ };
	
	time_t time_date = time(NULL);
	//~ printf("now %ld\n", time_date);
	struct tm time = *localtime(&time_date);
	//~ now 2025-09-24 18:11:08
	//~ printf("now %d-%02d-%02d %02d:%02d:%02d\n", time.tm_year+1900, time.tm_mon+1, time.tm_mday, time.tm_hour, time.tm_min, time.tm_sec);
	return time;
}

struct bin_tree *magic_table_init() {
	//~ struct H2_huff H2_huff_table[]
	struct bin_tree *btree;
	
	magic_table_btree = malloc(sizeof(struct bin_tree)*1000);
	
	magic_table_btree[0] = (binary_tree){0, NULL, {NULL, NULL}};
	
	int i=0, j=1, k=0, h=0; // j = 1 to skipe the default for unknow files
	
	while (magic_table[j][0])
	{
		btree = &magic_table_btree[0];
		h=0;
		
		while (1)
		{
			if (!magic_table[j][1][h])
			{
				btree->ptr = (void *)magic_table[j][0];
				break;
			}
			
			for (i = 0; i < 8; i++)
			{
				if (btree->next[BitVal(magic_table[j][1][h], i)] == NULL)
				{
					k++;
					magic_table_btree[k] = ((binary_tree){0, NULL, {NULL, NULL}});
					btree->next[BitVal(magic_table[j][1][h], i)] = &magic_table_btree[k];
					btree = &magic_table_btree[k];
				}
				else
				{
					btree = btree->next[BitVal(magic_table[j][1][h], i)];
				}
			}
			h++;
		}
		//~ printf("__%d\n",  j);
		j++;
	}
	
	//~ printf("_%d\n", k); //_236 _370 _512
	return &magic_table_btree[0];
}

struct buffer file_magic(struct H2_Frame *frm, struct buffer buff_save) {
	
	struct buffer data_save = ((binary_data){NULL,0});
	struct bin_tree *btree = &magic_table_btree[0];
	struct bin_tree *btree_save = NULL;
	int i=0, j=0;
	
	for (i = 0; i < buff_save.len; i++)
	{
		for (j = 0; j < 8; j++)
		{
			btree_save = btree->next[BitVal(buff_save.buff[i], j)];
			if (!btree_save)
			{
				if (i==0)
				{
					// TODO dynamic offset
					i=3; // offset for video/mp4 is 4 but 3 for i++.
					btree = &magic_table_btree[0];
					break;
				}
				
				return data_save;
			}
			else if (btree_save->next[0] == NULL && btree_save->next[1] == NULL)
			{
				data_save.buff = (char *)btree_save->ptr;
				data_save.len = strlen(data_save.buff);
				return data_save;
			}
			else
			{
				if (btree->ptr)
				{
					data_save.buff = (char *)btree->ptr;
					data_save.len = strlen(data_save.buff);
				}
				
				btree = btree->next[BitVal(buff_save.buff[i], j)];
			}
		}
	}
	
	return data_save;
}

int req_read(struct H2_connection *conn, char *chunk, int len) {
	
	
	struct pollfd plfd[1] = {{conn->fd, POLLIN, 0}};
	int chunkSize = -1, trackSize=0;
	
	//~ printf("__req__%d____\n",  len);
	
	while (trackSize<len)
	{
		if (conn->ssl && SSL_pending(conn->ssl) > 0)
		{
			chunkSize = SSL_read(conn->ssl, chunk+trackSize, len-trackSize);
			trackSize += chunkSize;
			continue;
		}
		
		//~ printf("__trackSize__%d____\n", trackSize);
		
		poll(plfd, 1, 0);
		//~ poll(plfd, 1, 0);
		if (plfd[0].revents & POLLIN) {
			//~ printf("-----EPOLLIN------\n");
			//~ printf("-----recv ------ %d\n", chunkSize);
			//~ printf("%s\n\n", chunk);
			
			if (conn->ssl)
			{chunkSize = SSL_read(conn->ssl, chunk+trackSize, len-trackSize);}
			else
			{chunkSize = recv(conn->fd, chunk+trackSize, len-trackSize, MSG_NOSIGNAL);}
			
			if (chunkSize == -1) {
				if (errno != EAGAIN) {
					/* real version needs to handle EINTR correctly */
					perror("read errno != EAGAIN");
					//~ exit(EXIT_FAILURE);
					return -1;
				}
				perror("read");
				return -1;
			}
			else if (chunkSize == 0)
			{
				return 0;
			}
			else
			{
				trackSize += chunkSize;
			}
		}
		else
		{
			//~ printf("----- POLLERR req_read ------\n");
			return -1;
		}
	}
	
	return trackSize;
}

int res_write(struct H2_connection *conn, char *payload, int len) {
	int e = -1;
	
	//~ struct pollfd plfd[1] = {{conn->fd, POLLOUT, 0}};
	//~ poll(plfd, 1, -1);
	//~ printf("res_write() send %s\n", buffer);
	//~ if (poll(plfd, 1, -1) == -1) {return -1}
	//~ if (plfd[0].revents & POLLOUT) {}
	
	if (conn->ssl)
	{
		e = SSL_write(conn->ssl, payload, len);
	}
	else
	{
		e = send(conn->fd, payload, len, MSG_NOSIGNAL);
	}
	
	//~ if(e==-1){perror("res_write");}
	
	return e;
}

//~ char *tes = "h2http/1.1";
int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg){
	
	//~ for (int i = 0; i < inlen; i++)
	//~ {
		//~ putchar(in[i]);
	//~ }
	//~ strcpy(*out, "h2");
	//~ strcpy(outlen, "2");
	
	if (!strscmp("\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", (char *)in, inlen))
	{
		*out = (unsigned char *)&in[1];
		*outlen = in[0];
	}
	else
	{
		// printf("alpn_cb:  %.*s\n", inlen, in);
		return -1;
	}
	
	return SSL_TLSEXT_ERR_OK;
}

SSL_CTX* sslctx_init() {
	//~ SSL_CTX *sslctx;
	sslctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_options(sslctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_mode(sslctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_min_proto_version(sslctx, TLS1_3_VERSION);
	
	//~ SSL_CTX_set_ciphersuites(sslctx, "TLS_CHACHA20_POLY1305_SHA256");
	//~ SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_OFF);
	
	//~ SSL_CTX_set_record_size_limit(sslctx, 512);
	//~ SSL_CTX_set_max_send_fragment(sslctx, 512);
	//~ SSL_CTX_set_split_send_fragment(sslctx, 64);
	SSL_CTX_set_tlsext_max_fragment_length(sslctx, 64);
	
	SSL_CTX_set_dh_auto(sslctx, 1);
	
	SSL_CTX_set_read_ahead(sslctx, 0);
	SSL_CTX_set_default_read_ahead(sslctx, 0);
	
	SSL_CTX_set_alpn_select_cb(sslctx, alpn_cb, NULL);
	//~ SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL );
	SSL_CTX_use_certificate_file(sslctx, "./localhost_ssl/localhost.crt", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(sslctx, "./localhost_ssl/localhost.key", SSL_FILETYPE_PEM);
	return sslctx;
}

SSL* H2_createSSL(struct H2_connection *conn) {
	int err=0;
	
	conn->ssl = SSL_new(sslctx);

	if (!conn->ssl)
	{
		printf("SSL_new 1 err \n");
		return NULL;
	}
	
	//~ SSL_set_max_send_fragment(conn->ssl, 512);
	
	SSL_set_fd(conn->ssl, conn->fd);
	SSL_accept(conn->ssl);
	err=SSL_get_error(conn->ssl, err);
	if (err<=1)
	{
		//~ printf("SSL_accept err %d  ____  \n", err);
		//~ res_write(conn, "HTTP/1.1 505 HTTP Version Not Supported\r\n\r\n", 43);
		return NULL;
	}
	
	//~ printf("____%d_____\n", SSL_SESSION_get_max_fragment_length(SSL_get1_session(conn->ssl)));
	
	char buffer[30];
	
	if (recv(conn->fd, buffer, 24, MSG_NOSIGNAL|MSG_PEEK)==0) //peek
	{
		return NULL;
	}
	
	if (SSL_read(conn->ssl, buffer, 24)>0 && !strncmp("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", buffer, 24))
	{
		return conn->ssl;
	}
	
	return NULL;
}

int ux_socket_connect(struct buffer poc_adrr) {
	
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1)
	{
		perror("ux socket err");
		return -1;
	}
	
	if (poc_adrr.len == -1)
	{
		poc_adrr.len = strlen(poc_adrr.buff);
	}
	
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	//~ ntoc(addr.sun_path+1, pid, 32);
	memcpy(addr.sun_path+1, poc_adrr.buff, poc_adrr.len);
	
	//~ sendto(sockfd, buff, len, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		//~ perror("ux_socket_connect error");
		return -1;
	}
	
	return sockfd;
}

int ux_socket_write(int sock_fd, struct buffer data, char type, char flags, int stream_id) {
	
	char header[9];
	ntoc(header, data.len, 24);
	header[3] = type; //0x0b
	header[4] = flags;
	ntoc(header+5, stream_id, 32);
	
	send(sock_fd, header, 9, MSG_NOSIGNAL);
	send(sock_fd, data.buff, data.len, MSG_NOSIGNAL);
	
	//~ close(sock_fd);
	
	return 0;
}

int ux_socket_listen(int pid) { // unix socket
	int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	
    if (sock_fd == -1)
	{
		perror("socket err");
		return -1;
	}
	
	//~ int on = 1;
	//~ fcntl(sock, O_NONBLOCK, (char *)&on);
	//~ ioctl(sock, FIONBIO, (char *)&on);
	
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	ntoc(addr.sun_path+1, pid, 32);
	
	//~ memcpy(addr.sun_path+1, data.buff, data.len);
	//~ warning: ‘memcpy’ reading 107 bytes from a region of size 30 sizeof(addr.sun_path)-1
	//~ printf("sockopt name__%s__\n", addr.sun_path+1);
	
    if (bind(sock_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1 || listen(sock_fd, 1) == -1) {
		perror("create unix Socket err\n");
		return -1;
	}
	
	return sock_fd;
}

int ip_socket_listen(int port) {
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	
    if (sock_fd == -1)
	{
		perror("socket err");
		return -1;
	}
	
	int on = 1;
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | 15, &on, sizeof(on))==-1) //SO_REUSEPORT = 15
	{
		printf("setsockopt err\n");
		return -1;
	}
	
	//~ ioctl(sock, FIONBIO, (char *)&on);
	//~ fcntl(sock, O_NONBLOCK, (char *)&on);
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port); /* Port number */
	addr.sin_addr.s_addr = htonl(INADDR_ANY); /* IPv4 address */
	
    if (bind(sock_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1 || listen(sock_fd, 1) == -1) {
		perror("createSocket err\n");
		return -1;
	}
	
	return sock_fd;
}

//~ int server_sent_event(struct H2_connection *conn, char *frame_head) {
	
	//~ struct H2_connection *conn_save = NULL; //conn_list;
	//~ while (conn_save)
	//~ {
		//~ if (conn_save->fd == cton(frame_head+5, 31))
		//~ {
			 //~ break;
		//~ }
		//~ conn_save = conn_save->conn_next;
	//~ }
	
	//~ if (!conn_save) return 0;
	
	//~ return 0;
//~ }

int add_conn_to_router(struct H2_connection *conn, struct buffer data, char type, char flags) { // just for to comunicat localy
	
	char chunk[4];
	int i = ux_socket_connect(((binary_data){"router_server_with_unix_socket",-1}));
	ntoc(chunk, proc_id, 32); // (char*)&proc_id is mirored
	switch (type)
	{
		case 0: //search
			ux_socket_write(i, conn->account_id, 0, flags, 0); //insert flag
			if (flags == 2)
			{
				ux_socket_write(i, ((binary_data){chunk, 4}), 1, 0, conn->fd); //insert
			}
			else
			{
				//~ ux_socket_read();
				//~ recv(conn->fd, chunk, len, MSG_NOSIGNAL);
			}
		break;
		case 1: //insert
			
		break;
		case 2: //delete
			
		break;
		case 3: //send
			
		break;
		default:
		break;
	}
	
	close(i);
	
	return i;
}

struct buffer str_prepare(struct buffer pos, char* str, struct buffer list[]) {
	int i=0, j=0, k=0;
	//~ char *rnd=NULL;
	struct buffer data = ((binary_data){NULL,0,NULL});
	
	while (str[0] && k<pos.len)
	{
		//~ printf("______%.*s______\n", k, pos.buff);
		switch (str[0])
		{
			case '?':
				if (list[i].buff)
				{
					if (k+list[i].len > pos.len) {break;}
					str_escape(pos, &k, list[i]);
				}
				else if (list[i].len>-1 && k+10<pos.len)
				{
					//~ 2025-09-24 18:11:08 example
					k += numstr(pos, k, list[i].len).len;
				}
				else
				{
					k--;
					strcpy(pos.buff+k, "NULL");
					k+=4;
					str++;
				}
				
				i++;
			break;
			case '%':
				while (1)
				{
					str++;
					if (str[0]!='%')
					{
						j=(j<<3)+(j<<1);
						j+=str[0]&0xF;
					}
					else
					{
						break;
					}
				}
				
				if (k+j>pos.len) {break;}
				data.next=random_char(pos.buff+k, j);
				
				k+=j;
			break;
			default:
				pos.buff[k]=str[0];
				k++;
		}
		str++;
	}
	pos.buff[k]='\0';
	
	data.buff=pos.buff;
	data.len=k;
	
	return data;
}

/*
struct buffer sql_json_response(MYSQL *dbconn, struct buffer data_stack) {
	// 
	MYSQL_RES *query_res = mysql_store_result(dbconn);
	if (!query_res)
	{
		// Report the failed-connection error & close the handle
		//~ fprintf(stderr, "sql_json_response Error : %s\nmysql_errno: %d\n", mysql_error(dbconn), mysql_errno(dbconn));
		//~ mysql_close(dbconn);
		return ((binary_data){NULL,0});
	}
	
	//~ int total_json_lenght=0;
	//~ MYSQL_ROWS *data_json = query_res->data->data;
	
	//~ do
	//~ {
		//~ printf("total_json_lenght _________%lld______\n", query_res->data->rows);
		//~ total_json_lenght += data_json->length;
		//~ data_json=data_json->next;
	//~ }
	//~ while (data_json);
	
	int totalrows = mysql_num_rows(query_res);
	int numfields = mysql_num_fields(query_res);
	MYSQL_FIELD *fields = mysql_fetch_fields(query_res);
	unsigned long *length;
	
	if (totalrows==0 || numfields==0)
	{
		mysql_free_result(query_res);
		return ((binary_data){NULL,0});
	}
	
	//~ data.len = totalrows*numfields*100;
	
	//~ data_stack.len = thread_chunk_size;
	
	MYSQL_ROW row;
	int i=0, k=0;
	//~ strcpy(data_stack.buff+k, "["); k++;
	str_escape(data_stack, &k, ((binary_data){"[", 1}));
	
	while((row = mysql_fetch_row(query_res)))
	{
		length = mysql_fetch_lengths(query_res);
		str_escape(data_stack, &k, ((binary_data){"[", 1}));
		for(i = 0; i < numfields; i++)
		{
			//~ printf("Field %u is %ld\n", i, fields[i].length);
			//~ printf("select;_____ %s_____ %ld\n", row[i], length[i]);
			switch (fields[i].type)
			{
				case 2:
				case 3:
				case 4:
				case 5:
				case 8:
				case 9:
				case 246:
					str_escape(data_stack, &k, ((binary_data){row[i], length[i]}));
					break;
				case 245: //MYSQL_TYPE_JSON
				case 249:
				case 250:
				case 251:
				case 252: //MYSQL_TYPE_BLOB
					if (data_stack.len > k+length[i])
					{
						strncpy(data_stack.buff+k, row[i], length[i]); 
						k+=length[i];
					}
					break;
				case 6:
					str_escape(data_stack, &k, ((binary_data){"null", 4}));
					break;
				default:
					if (length[i]==0)
					{
						str_escape(data_stack, &k, ((binary_data){"null", 4}));
					}
					else
					{
						if (data_stack.len>k){data_stack.buff[k]='\"';} k++;
						str_escape(data_stack, &k, ((binary_data){row[i], length[i]}));
						if (data_stack.len>k){data_stack.buff[k]='\"';} k++;
					}
					
			}
			str_escape(data_stack, &k, ((binary_data){",", 1}));
		}
		k--;
		str_escape(data_stack, &k, ((binary_data){"],", 2}));
	}
	k--;
	str_escape(data_stack, &k, ((binary_data){"]", 1}));
	if (data_stack.len>k){data_stack.buff[k]='\0';}
	
	mysql_free_result(query_res);
	
	data_stack.len = k;
	return data_stack;
}

MYSQL *sql_connect() {
	// Initialize Connection
	MYSQL *dbconn;
	if (!(dbconn = mysql_init(0)))
	{
	  fprintf(stderr, "sql_connect: unable to initialize connection struct\n");
	  return NULL;
	}
	
	// Connect to the database  CLIENT_MULTI_STATEMENTS
	if (!mysql_real_connect(dbconn, "localhost", "user", "user", "qwartz", 3306, NULL, 0))
	{
	  // Report the failed-connection error & close the handle
	  fprintf(stderr, "Error connecting to Server: %s\nmysql_errno: %d\n", mysql_error(dbconn), mysql_errno(dbconn));
	  //~ mysql_close(dbconn);
	  //~ return NULL;
	}
	
	mysql_autocommit(dbconn, 1);
	
	return dbconn;
	
	//~ mysql_reset_connection(dbconn);
	//~ mysql_close(dbconn);
}

int sql_request(MYSQL *dbconn, struct buffer query) {
	int a = mysql_real_query(dbconn, query.buff, query.len);
	if(a)
	{
		if(mysql_errno(dbconn) == 2006) //CR_SERVER_GONE_ERROR /usr/include/mysql/errmsg.h
		{
			//~ fprintf(stderr, "CR_SERVER_GONE_ERROR connecting to Server: %s\nmysql_errno: %d\n", mysql_error(dbconn), mysql_errno(dbconn));
			mysql_close(dbconn);
			dbconn = sql_connect();
			a = mysql_real_query(dbconn, query.buff, query.len);
		}
		else
		{
			//~ // Report the failed-connection error & close the handle
			//~ fprintf(stderr, "Error in query: %s\nmysql_errno: %d\n", mysql_error(dbconn), mysql_errno(dbconn));
			//~ // mysql_close(dbconn);
		}
	}
	
	//~ sql_json(dbconn);
	return a;
}
*/

struct bin_tree *headers_path_table_init() {
	//~ struct H2_huff H2_huff_table[]
	struct bin_tree *btree;
	void *data_save[3];
	char *data_save_2;
	
	headers_path_table_btree = malloc(sizeof(struct bin_tree)*1000);
	
	headers_path_table_btree[0] = (binary_tree){0, NULL, {NULL, NULL}};
	
	int i=0, j=0, k=0, h=0, z=0;
	
	while (headers_path_table[j][0])
	{
		btree = &headers_path_table_btree[0];
		data_save[0] = (void*)headers_path_table[j][0];
		data_save[1] = (void*)headers_path_table[j][1];
		data_save[2] = (void*)headers_path_table[j][2];
		
		for (z = 0; z < 2; z++) // for method then path
		{
			h=0;
			while (1)
			{
				data_save_2 = data_save[z];
				
				if (!data_save_2 || !data_save_2[h])
				{
					if (z==1) // path
					{
						btree->ptr = data_save[2];
					}
					break;
				}
				
				for (i = 0; i < 8; i++)
				{
					if (btree->next[BitVal(data_save_2[h], i)] == NULL)
					{
						k++;
						headers_path_table_btree[k] = ((binary_tree){0, NULL, {NULL, NULL}});
						btree->next[BitVal(data_save_2[h], i)] = &headers_path_table_btree[k];
						btree = &headers_path_table_btree[k];
					}
					else
					{
						btree = btree->next[BitVal(data_save_2[h], i)];
					}
				}
				//~ printf("__%d\n",  h);
				h++;
			}
			
		}
		
		j++;
		
		//~ while (1)
		//~ {
			//~ data_save = ((char*)headers_path_table[j][1]);
			
			//~ if (!data_save || !data_save[h])
			//~ {
				//~ btree->num = ((char*)headers_path_table[j][0])[0];
				//~ btree->ptr = headers_path_table[j][2];
				//~ // printf("_%d__-%c-__%p__\n", btree->num, data_save[h], btree->ptr);
				//~ break;
			//~ }
			
			//~ for (i = 0; i < 8; i++)
			//~ {
				//~ if (btree->next[BitVal(data_save[h], i)] == NULL)
				//~ {
					//~ k++;
					//~ headers_path_table_btree[k] = ((binary_tree){0, NULL, {NULL, NULL}});
					//~ btree->next[BitVal(data_save[h], i)] = &headers_path_table_btree[k];
					//~ btree = &headers_path_table_btree[k];
				//~ }
				//~ else
				//~ {
					//~ btree = btree->next[BitVal(data_save[h], i)];
				//~ }
			//~ }
			//~ // printf("__%d\n",  h);
			//~ h++;
		//~ }
		//~ j++;
	}
	
	//~ printf("_%d\n", k); //_236 _370 _512
	return &headers_path_table_btree[0];
}

void *headers_path_table_search(struct buffer list[]) {
	
	struct bin_tree *btree = &headers_path_table_btree[0];
	struct bin_tree *btree_save = btree;
	int i=0, j=0, k=0;
	
	while (list[k].buff)
	{
		for (i = 0; i < list[k].len; i++)
		{
			for (j = 0; j < 8; j++)
			{
				btree_save = btree->next[BitVal(list[k].buff[i], j)];
				//~ printf("_%d___%c___%p__\n", btree->num, buff_save.buff[i], btree->ptr);
				if (!btree_save)
				{
					return NULL;
				}
				else if (btree_save->next[0] == NULL && btree_save->next[1] == NULL) // leaf
				{
					return btree_save->ptr;
				}
				else
				{
					btree = btree->next[BitVal(list[k].buff[i], j)];
				}
			}
		}
		
		k++;
	}
	
	if (btree_save) {return btree_save->ptr;} else {return NULL;}
}

struct H2_header *H2_get_header(struct H2_header *H2_header, int header) {
	//~ struct H2_header *header = frm->request->headers;
	int i=0, j=0;
	
	struct H2_header *H2_header_save = H2_header;
	struct H2_header *H2_header_save_2;
	
	if (header <= 61)
	{
		return NULL;
	}
	
	j = header-61;
	
	while (H2_header_save)
	{
		if (i==j)
		{
			H2_header_save_2 = H2_header;
			
			if (H2_header_save->name.buff)
			{
				break;
			}
			
			while (H2_header_save_2)
			{
				//~ printf("___%d\n", j);
				if (!H2_header_save_2->name.buff && H2_header_save_2->name.len == H2_header_save->name.len)
				{
					return H2_header_save_2;
				}
				
				H2_header_save_2 = H2_header_save_2->next;
			}
			
			break;
		}
		
		H2_header_save = H2_header_save->next;
		i++;
	}

	return H2_header_save;
}

int H2_encode_header(char *data_save, int number, int prefixNbits) { // represent an integer with HPACK
    
    //~ if I < 2^N - 1, encode I on N bits
	//~ else
	//~ encode (2^N - 1) on N bits
	//~ I = I - (2^N - 1)
	//~ while I >= 128
	//~ encode (I % 128 + 128) on 8 bits
	//~ I = I / 128
	//~ encode I on 8 bits
    
	//~ printf("___%d\n", ((0x01<<prefixNbits)-1));
	int i=0;
	if (number < ((0x01<<prefixNbits)-1))
	{
		ntoc(data_save+i, number, 8);
	}
	else if (number == (0x01<<prefixNbits)-1)
	{
		ntoc(data_save+i, ((0x01<<prefixNbits)-1), 8);
		i++;
		ntoc(data_save+i, 0, 8);
	}
	else
	{
		ntoc(data_save+i, ((0x01<<prefixNbits)-1), 8);
		number-=((0x01<<prefixNbits)-1);
		while (number>=128)
		{
			i++;
			ntoc(data_save+i, ((number%128)+128), 8);
			number>>=7;
		}
		
		i++;
		ntoc(data_save+i, number, 8);
	}
	
	i++;
	return i;
}

int H2_decode_header(char **buffer, int prefixNbits, char *end) { // decode an integer with HPACK, it will auto increment the address of pointer buffer
    int i = 0, result = 0;
    
    //~ decode I from the next N bits
	//~ if I < 2^N - 1, return I
	//~ else
	//~ M = 0
	//~ repeat
	//~ B = next octet
	//~ I = I + (B & 127) * 2^M
	//~ M = M + 7
	//~ while B & 128 == 128
	//~ return I
    
	//~ printf("_%p\n", *buffer);
	result = cton(*buffer, prefixNbits);
	
	if (result >= (0x01<<prefixNbits)-1)
	{
		do {
			(*buffer)++;
			//~ printf("___er:_%d__%d__%d__%d__\n", ((*buffer[0] & 0x7F) << i), i, result, prefixNbits);
			result += ((*buffer[0] & 0x7F) << i);
			i += 7;
		} while ((*buffer[0] & 0x80) == 0x80 && *buffer < end);
	}
	
	(*buffer)++;
	
	return result;
}

void H2_add_Frame(struct H2_connection *conn, struct H2_Frame *frm) {
	int i=0, k=0, weight=0;
	if (conn->frm_id==0)
	{
		conn->frm_id = frm->stream_id;
	}
	else if(conn->frm_id!=frm->stream_id && frm->next_id==0 && frm->prev_id==0)
	{
		if (conn->stream_id[frm->dpnd_id]
			&& conn->stream_id[frm->dpnd_id]->type == 0x2) // type PRIORITY
		{
			//~ i = conn->stream_id[frm->dpnd_id]->weight >> 5;
			//~ frm->next_id = conn->frm[i];
			//~ conn->frm[i] = frm->stream_id;
			weight = conn->stream_id[frm->dpnd_id]->weight;
		}
		else
		{
			weight = frm->weight;
		}
		
		i = conn->frm_id;
		
		//~ printf("i: %d\n",i);
		
		while (conn->stream_id[i] && conn->stream_id[i]->weight > weight)
		{
			k = i;
			i = conn->stream_id[i]->next_id;
			if (i==0)
			{
				break;
			}
		}
		
		if (conn->frm_id == i)
		{
			frm->next_id = i;
			conn->frm_id = frm->stream_id;
			
			if (conn->stream_id[i])
			{
				conn->stream_id[i]->prev_id = frm->stream_id;
			}
		}
		else if (i!=0)
		{
			frm->next_id = i;
			frm->prev_id = conn->stream_id[i]->prev_id;
			conn->stream_id[i]->prev_id = frm->stream_id;
			conn->stream_id[frm->prev_id]->next_id = frm->stream_id;
		}
		else
		{
			frm->next_id = 0;
			frm->prev_id = k;
			conn->stream_id[k]->next_id = frm->stream_id;
		}
	}
}

void H2_reset_stream(struct H2_connection *conn, int stream_id) {
	int i = 0;
	struct H2_Frame *frm = conn->stream_id[stream_id];
	
	if (!frm){}
	else if(conn->frm_id == frm->stream_id)
	{
		//~ printf("H2_reset_stream stream_id: %d\n",frm->stream_id);
		//~ printf("H2_reset_stream next_id: %d\n",frm->next_id);
		conn->frm_id = frm->next_id;
		frm->next_id = 0;
		frm->prev_id = 0;
	}
	else
	{
		i = frm->prev_id;
		if (conn->stream_id[i])
		{
			conn->stream_id[i]->next_id = frm->next_id;
		}
		
		i = frm->next_id;
		
		if (conn->stream_id[i])
		{
			conn->stream_id[i]->prev_id = frm->prev_id;
		}
		
		frm->prev_id = 0;
		conn->stream_id[stream_id]->next_id = 0;
	}
	
	//~ H2_free_stream(conn, stream_id);
}
void H2_free_header(struct H2_header *header){
	
	struct H2_header *header_save = NULL;
	
	while (header != NULL)
	{
		header_save = header->next;
		if (header->name.buff){free(header->name.buff);}
		if (header->value.buff){free(header->value.buff);}
		free(header);
		header = header_save;
	}
	
}
void H2_free_stream(struct H2_connection *conn, int stream_id) {
	H2_reset_stream(conn, stream_id);
	struct H2_Frame *frm = conn->stream_id[stream_id];
	conn->stream_id[stream_id] = NULL;
	if (frm){
		struct buffer *data = NULL;
		while (frm->request->chunk_struct != NULL)
		{
			data = frm->request->chunk_struct->next;
			free(frm->request->chunk_struct->buff);
			free(frm->request->chunk_struct);
			frm->request->chunk_struct = data;
		}
		
		if (frm->request->file.fd>0)
		{
			close(frm->request->file.fd);
			if (frm->request->method.len == 3 && frm->request->file.finish == 0 && frm->request->file.path.buff) {
				unlink(frm->request->file.path.buff);
			}
		}
		
		//~ if (frm->request->fid.buff) {free(frm->request->fid.buff);} // part of fpath
		//~ if (frm->request->ftype.buff) {free(frm->request->ftype.buff);} // do not free, its point to magic table
		if (frm->request->file.path.buff) {free(frm->request->file.path.buff);}
		
		H2_free_header(frm->request->headers);
		
		if (frm->request){free(frm->request);}
		free(frm);
		
		//~ printf("-----------_free(frm);_---\n");
	}
}

void H2_free_connection(struct H2_connection *conn) {
	conn_list[conn->fd] = NULL;
	
	close(conn->fd);
	conn->fd = 0;
	
	while (mtx_trylock(&conn->ready) == EBUSY)
	{
		mtx_unlock(&conn->ready);
	}
	
	mtx_destroy(&conn->ready);
	
	if (conn->account_id.buff){free(conn->account_id.buff);}
	
	if (conn->frame_payload.buff) {free(conn->frame_payload.buff);}
	
	for (int i=0; i < MAX_CONCURRENT_STREAMS; i++)
	{
		H2_free_stream(conn, i);
	}
	
	H2_free_header(conn->dynamic_table);
	
	if (conn->ssl) {
		//~ SSL_shutdown(conn->ssl);
		//~ SSL_clear(conn->ssl);
		//~ SSL_certs_clear(conn->ssl);
		//~ SSL_SESSION_free(SSL_get1_session(ssl));
		//~ SSL_CTX_flush_sessions(sslctx, 0);
		//~ SSL_CTX_free(SSL_get_SSL_CTX(conn->ssl));
		SSL_free(conn->ssl);
	}
	
	//~ printf("pointer %p\n", conn);
	memset(conn, '\0', sizeof(struct H2_connection));
	
	free(conn);
	
	mtx_lock(&client_accepted_mutex);
	
	client_accepted--;
	
	if (conn_sock==-1 && client_accepted<max_client_accepted) {
		struct epoll_event ev;
		conn_sock = ip_socket_listen(8080);
		ev.events = EPOLLIN|EPOLLET;
		//~ ev.data.ptr = malloc(sizeof(struct H2_connection));
		ev.data.fd = conn_sock;
		epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev);
	}
	
	mtx_unlock(&client_accepted_mutex);
	
	//~ struct H2_connection *conn_save = conn_list;
	
	//~ if (conn_save == conn)
	//~ {
		//~ mtx_lock(&conn_list_mutex);
		//~ conn_list = conn_list->conn_next;
		//~ mtx_unlock(&conn_list_mutex);
	//~ }
	//~ else {
		//~ while (conn_save)
		//~ {
			//~ if (conn_save->conn_next == conn)
			//~ {
				//~ mtx_lock(&conn_list_mutex);
				//~ conn_save->conn_next = conn->conn_next;
				//~ mtx_unlock(&conn_list_mutex);
				//~ break;
			//~ }
			//~ conn_save = conn_save->conn_next;
		//~ }
	//~ }
	
	//~ printf("\n_________________all free___________________\n");
	//~ return;
}

int H2_req_peek(struct H2_connection *conn, char *chunk, int len) {
	
	int chunkSize = -1;
	
	if (mtx_lock(&conn->ready) > 0){return -1;}
	
	if (conn->ssl)
	{chunkSize = SSL_peek(conn->ssl, chunk, len);}
	else
	{chunkSize = recv(conn->fd, chunk, len, MSG_NOSIGNAL|MSG_PEEK);}
	
	mtx_unlock(&conn->ready);
	
	return chunkSize;
}

int H2_req_read(struct H2_connection *conn, char *chunk, int len) {
	int chunkSize = -1;
	if (mtx_lock(&conn->ready) > 0){return -1;}
	chunkSize = req_read(conn, chunk, len);
	mtx_unlock(&conn->ready);
	
	return chunkSize;
}

int H2_res_write(struct H2_connection *conn, int len, char type, char flags, int stream_id, char *payload) {
	char header[9];
	int chunkSize = -1;
	
	//~ if (!payload || len==0) // ???
	//~ {
		//~ return chunkSize;
	//~ }
	
	if (len==-1)
	{
		len=strlen(payload);
	}
	
	ntoc(header, len, 24);
	header[3] = type;
	header[4] = flags;
	ntoc(header+5, stream_id, 32);
	//~ Length			Type	Flags	1 bit Reserved + Stream Id
	//~	\x00\x00\x1e	\x04	\x00	\x00\x00\x00\x00\	 //Frame Format exemple
	
	if (mtx_lock(&conn->ready) > 0) return -1;
	
	chunkSize = res_write(conn, header, 9);
	if (chunkSize>0 && len>0)
	{
		chunkSize = res_write(conn, payload, len);
		//~ if(chunkSize==-1){perror("res_write");}
	}
	
	mtx_unlock(&conn->ready);
	
	return chunkSize;
}

int H2_res_writeHead(struct H2_Frame *frm, struct buffer list[]) {
	int i=0, k=0;
	char *end = frm->conn->headers_reuse.buff;
	char *c;
	
	//~ printf("res_writeHead() %s\n", buffer[0]);
	//~ if(res_write(frm, "HTTP/1.1 ", 9)==-1) {perror("res_writeHead00");return -1;}
	
	while ((list[i].buff || list[i].len>0) && frm->conn->headers_reuse.len>k )
	{
		if (list[i].buff)
		{
			//~ Index
			k+=H2_encode_header(end+k, list[i].len, 4);
			
			//~ Value
			k+=H2_encode_header(end+k, strlen(list[i].buff), 7);
			strcpy(end+k, list[i].buff);
			k+=strlen(list[i].buff);
			
			//~ printf("\n");
			//~ for ( i = 0; i < k; i++) {
				//~ printf("_%02x", (unsigned)(end)[i] & 0xFF);
			//~ }
			//~ printf("\n");
		}
		else
		{
			c=end+k;
			k+=H2_encode_header(end+k, list[i].len, 7);
			SetBit(c[0],7);
		}
		
		i++;
	}
	
	//~ for (int i = 0; i < k; i++) {
		//~ printf("_%c", (unsigned)(end)[i] & 0xFF);
	//~ }
		
	H2_res_write(frm->conn, k, 1, 4, frm->stream_id, end);
	
	//~ i = res_write(frm, header, (end-header));
	return i;
}

struct bin_tree *H2_huff_table_init() {
	//~ struct H2_huff H2_huff_table[]
	struct bin_tree *btree;
	
	huff_btree = malloc(sizeof(struct bin_tree)*1000);  //4688 _512
	
	huff_btree[0] = ((binary_tree){0, NULL, {NULL, NULL}});
	
	int k=0, i=0, j=0;
	
	//~ for (; i < 257; i++)
	
	while(H2_huff_table[i][0] != 0)
	{
		btree = &huff_btree[0];
		for (j = H2_huff_table[i][0]-1; j >= 0; j--)
		{
			//~ printf("__%d\n",  j);
			if (btree->next[BitVal(H2_huff_table[i][1], j)] == NULL)
			{
				k++;
				btree->next[BitVal(H2_huff_table[i][1], j)] = &huff_btree[k];
				huff_btree[k] = ((struct bin_tree){0, NULL, {NULL, NULL}});
				btree = &huff_btree[k];
			}
			else
			{
				btree = btree->next[BitVal(H2_huff_table[i][1],j)];
			}
		}
		//~ printf("__%x\n",  i);
		btree->num = i;
		i++;
	}
	
	//~ printf("_%d\n", k); //_236 _370 _512
	return &huff_btree[0];
}

struct buffer H2_huff_table_search(char **buffer, char *buff_end) {
	//~ struct H2_huff H2_huff_table[]
	struct bin_tree *btree = &huff_btree[0];
	struct bin_tree *btree_save = NULL;
	struct buffer buffStruct = ((binary_data){NULL,0});
	
	int isHuffmanEncoded = BitVal(*buffer[0], 7),
	len = H2_decode_header(buffer, 7, buff_end),
	j=0, i=0;
	
	char *buff = malloc((len*2)*sizeof(char)+1);
	char *end = buff;
	buffStruct.buff = buff;
	
	for (i = 0; i < len && *buffer < buff_end; i++)
	{
		if (isHuffmanEncoded==1) // huffman encoded ?
		{
			for (j = 7; j >= 0; j--)
			{
				btree_save = btree->next[BitVal(*buffer[0], j)];
				//~ printf("_%d_%c\n", j, btree->next[BitVal(buffer[i], j)]->value);
				if (!btree_save)
				{
					btree = &huff_btree[0];
				}
				else if (btree_save->next[0] == NULL && btree_save->next[1] == NULL)
				{
					//~ printf("__%d\n", BitVal(buffer[i], j));
					end[0] = btree_save->num;
					end++;
					btree = &huff_btree[0];
				}
				else
				{
					btree = btree_save;
				}
			}
		}
		else
		{
			end[0] = *buffer[0];
			end++;
		}
		
		(*buffer)++;
	}
	
	//~ printf("__old:_%d___new:__%ld____\n", (len*2), (end-buff));
	
	// TODO realloc buffer to the exact size
	// not needed, because the exact size is not that far from the (len*2)
	
	end[0] = '\0';
	buffStruct.len=end-buff;
	return buffStruct;
}

int H2_parse_settings(struct H2_connection *conn, char *buffer, int len) {
	int i=0;
	int max_frame_size=0;
	
	while (len>i)
	{
		switch (cton(buffer+i, 16))
		{
			case 4: //INITIAL_WINDOW_SIZE
				conn->client_initial_window_size = cton(buffer+i+2, 32);
				//~ conn->send_window = conn->client_initial_window_size;
				//~ printf("INITIAL_WINDOW_SIZE: %d \n", conn->client_initial_window_size);
			break;
			case 5: //SETTINGS_MAX_FRAME_SIZE
				max_frame_size = cton(buffer+i+2, 31);
			break;
			default:
			break;	
		}
		i+=6;
		//~ printf("INITIAL_WINDOW_SIZE: %d \n", conn->initial_window_size);
	}
	
	/*##########################################################################################*/
	
	if (conn->client_max_frame_size != max_frame_size && max_frame_size>0)
	{
		conn->client_max_frame_size = max_frame_size;
		
		if (conn->frame_payload.buff) {free(conn->frame_payload.buff);}
		conn->frame_payload.buff = malloc(sizeof(char)*conn->client_max_frame_size);
		conn->frame_payload.len = conn->client_max_frame_size;
	}
	
	return 0;
}

struct H2_request *H2_parse_headers(struct H2_Frame *frm, struct H2_connection *conn) {
	
	char *buffer = conn->frame_payload.buff;
	int header=0;
	char *end = buffer+frm->len;
	struct H2_header *head = NULL;
		
	struct H2_request *req = malloc(sizeof(struct H2_request));
	req->method = ((binary_data){NULL,0});
	req->path = ((binary_data){NULL,0});
	req->headers = NULL;
	req->chunk_struct = NULL;
	req->application = NULL;
	
	req->file.fd = 0;
	req->file.id = ((binary_data){NULL,0});
	req->file.path = ((binary_data){NULL,0});
	req->file.type = ((binary_data){NULL,0});
	req->file.size = 0;
	req->file.finish = 0;
	
	//~ memset(&req->ftime, 0, sizeof(struct tm));
	
	
	if (BitVal(frm->flags, 3) == 1) //PADDED Flag
	{
		//~ printf("\n____Pad_Length: %d \n", cton(buffer, 8));
		buffer++; // skipe the pading size byte
		end-=(cton(conn->frame_payload.buff, 8)-1);
	}
	
	if (BitVal(frm->flags, 5) == 1) //PRIORITY Flag
	{
		//~ printf("____Exclusive: %d \n", BitVal(buffer[0], 7));
		//~ printf("____Stream_Dependency: %d \n", cton(buffer, 31));
		frm->dpnd_id = cton(buffer, 31);
		//~ printf("____Weight: %d \n", cton(conn->frame_payload.buff+4, 8));
		frm->weight = cton(conn->frame_payload.buff+4, 8);
		buffer += 5;
	}
		
	while (buffer < end)
	{
		head = NULL;
		header=0;
		
		//~ printf("____next header _%d___%d_\n",(int)(end-buffer), frm->len);
		if (BitVal(buffer[0], 7) == 1) //&0x80
		{
			// prefixN = 7;
			// Indexed Header Field
			
			if (cton(buffer, 7) > 0) // Indexed
			{
				header = H2_decode_header(&buffer, 7, end); 
				//~ printf("___7_Header: %d \n", header);
				
				head = H2_get_header(conn->dynamic_table, header);
				if (head && !head->name.buff)
				{
					header = head->name.len;
				}
				
				//~ printf("__7_Header: %d \n", header);
				
				switch (header)
				{
					case 2:
						req->method = ((binary_data){(char*)H2_static_table[2][1], 3}); // "GET" lenght is 3
						break;
					case 3:
						if (head && !head->name.buff && head->name.len==0)
						{
							req->method = head->value;
							break;
						}
						req->method = ((binary_data){(char*)H2_static_table[3][1], 4}); // "POST" lenght is 4
						break;
					case 4:
					case 5:
						req->path.buff = NULL;
						req->path.len = header;
						break;
					default:
						break;
				}
			}
			else // not indexed == 0
			{
				// error here
				return req;
			}
		}
		else if (BitVal(buffer[0], 6) == 1) //&0x40
		{
			conn->dynamic_table_len+=32;
			
			// prefixN = 6;
			// Literal Header Field with Incremental Indexing
			
			/*
				A literal header field with incremental indexing representation
				results in appending a header field to the decoded header list and
				inserting it as a new entry into the dynamic table.
			*/
						
			head = malloc(sizeof(struct H2_header));
			head->next = conn->dynamic_table;
			head->prev = NULL;
			head->pos = 0;
			
			if (!conn->dynamic_table)
			{
				conn->dyn_table_last = head;
			}
			
			if (conn->dynamic_table)
			{
				conn->dynamic_table->prev = head;
			}
			
			conn->dynamic_table = head;
			
			if (cton(buffer, 6) > 0) // -- Indexed Name
			{
				header = H2_decode_header(&buffer, 6, end);
				//~ printf("___6__header: %d \n",header);
				
				head = H2_get_header(conn->dynamic_table, header);
				if (head && !head->name.buff)
				{
					header = head->name.len;
				}
				
				//~ printf("___6__header: %d \n",header);
				conn->dynamic_table->name.buff = NULL;
				conn->dynamic_table->name.len = header;
			}
			else // -- New Name
			{
				buffer++; // +1 byte for the Index byte
				conn->dynamic_table->name = H2_huff_table_search(&buffer, end);
				conn->dynamic_table_len += conn->dynamic_table->name.len;
			}
					
			//~ printf("____Huffman: %d ", BitVal(buffer[0], 7));
			//~ printf("____Length: %d ", (cton(buffer, 7)));
			//~ printf("___char: %b ", buffer[0] & 0xff);
			
			conn->dynamic_table->value = H2_huff_table_search(&buffer, end);
			conn->dynamic_table_len += conn->dynamic_table->value.len;
			
			//~ printf("__6__conn->dynamic_table_len: %d \n",conn->dynamic_table_len);
			//~ printf("__6__String: %.*s \n",conn->dynamic_table->value.len, conn->dynamic_table->value.buff);
			
			switch (header)
			{
				case 1:
					conn->authority = conn->dynamic_table->value;
					break;
				case 2:
				case 3:
					req->method = conn->dynamic_table->value;
					break;
				case 32:
					conn->cookie = conn->dynamic_table->value;
					break;
				default:
					break;
			}
			
			
			
			// it will break the referenced pointers to dynamic table
			//~ while (conn->dynamic_table_len > MAX_HEADER_LIST_SIZE) {
				//~ conn->dynamic_table_len -= 32;
				//~ conn->dynamic_table_len -= conn->dyn_table_last->name.len;
				//~ conn->dynamic_table_len -= conn->dyn_table_last->value.len;
				//~ head = conn->dyn_table_last;
				//~ conn->dyn_table_last = head->prev;
				//~ H2_free_header(head);
			//~ }
					
			//~ printf("____%d\n", header);
			//~ buffer+=cton(buffer, 7);
		}
		else if (BitVal(buffer[0], 5) == 1) //&0x20
		{
			//~ prefixN = 5;
			// Maximum Dynamic Table Size Change
			/*
				A dynamic table size update starts with the '001' 3-bit pattern,
				followed by the new maximum size, represented as an integer with a
				5-bit prefix (see Section 5.1).
			 */
			 
			header = H2_decode_header(&buffer, 5, end); 
			//~ printf("___Maximum Dynamic Table Size Change: %d \n", header);
		}
		else if (BitVal(buffer[0], 4) == 1 || BitVal(buffer[0], 4) == 0) //&0x10
		{
			// &0x10 == 1
			// prefixN = 4; 
			// Literal Header Field Never Indexed
			//~ printf("4");
			/*
				A literal header field never-indexed representation results in
				appending a header field to the decoded header list without altering
				the dynamic table.  Intermediaries MUST use the same representation
				for encoding this header field.
			*/
			
			// &0x10 == 0
			//~ prefixN = 4;
			// Literal Header Field without Indexing
			/*
				A literal header field without indexing representation results in
				appending a header field to the decoded header list without altering
				the dynamic table.
			 */
			
			head = malloc(sizeof(struct H2_header));
			head->next = req->headers;
			head->prev = NULL;
			
			if (req->headers)
			{
				req->headers->prev = head;
			}
			
			req->headers = head;
			
			if (cton(buffer, 4) > 0) // indexed header
			{
				header = H2_decode_header(&buffer, 4, end); 
				req->headers->name.buff = NULL;
				req->headers->name.len = header;
				//~ printf("___Header: %d ", header);
			}
			else // not indexed header
			{
				buffer++; // +1 byte for the Index byte
				req->headers->name = H2_huff_table_search(&buffer, end);
				//~ printf("____String: %s ",H2_huff_table_search(&buffer).buff);
			}
			
			// value :
			req->headers->value = H2_huff_table_search(&buffer, end);
			
			//~ printf("__4__String: %.*s \n",req->headers->value.len, req->headers->value.buff);
			
			switch (header)
			{
				case 4:
				case 5:
					req->path = req->headers->value;
					break;
				default:
					break;
			}
			
		}
		//~ printf("\n");
	}
		
	req->application = headers_path_table_search((array{req->method, req->path, {NULL,0}}));
	
	return req;
}

struct H2_connection *H2_connection_init(int fd) {
	
    struct H2_connection *conn = NULL;
	int i=0;
	
	conn = malloc(sizeof(struct H2_connection));
	conn->fd = fd;
	conn->ssl = NULL;
	mtx_init(&conn->ready, 0);
	conn->dynamic_table = NULL;
	conn->dynamic_table_len = 0;
	conn->authority = ((binary_data){NULL,0});
	conn->cookie = ((binary_data){NULL,0});
	conn->account_id = ((binary_data){NULL,0});
	conn->event_frm_id = 0;
	conn->frm_id = 0;
	conn->send_window = SETTINGS_INITIAL_WINDOW_SIZE;
	conn->recv_window = SETTINGS_INITIAL_WINDOW_SIZE;
	conn->client_initial_window_size = SETTINGS_INITIAL_WINDOW_SIZE;
	conn->client_max_frame_size = MAX_FRAME_SIZE;
	//~ conn->conn_next = NULL;
	conn->frame_payload = ((binary_data){malloc(sizeof(char)*MAX_FRAME_SIZE),MAX_FRAME_SIZE});
	conn->headers_reuse = ((binary_data){malloc(sizeof(char)*max_chunk_size),max_chunk_size});
	conn->ptr = NULL;
	
	//~ memset(&conn->stream_id, 0, sizeof(struct H2_Frame*)*MAX_CONCURRENT_STREAMS);
	
	for (i = 0; i < MAX_CONCURRENT_STREAMS; i++)
	{
		conn->stream_id[i] = NULL;
	}
	
	return conn;
}

struct H2_Frame *H2_Frame_init(struct H2_connection *conn, char *frame_head) { // only for headers frame, no need for other types
	
    struct H2_Frame *frm = NULL;
	
	frm = malloc(sizeof(struct H2_Frame));
	frm->len = cton(frame_head, 24);
	frm->type = frame_head[3]&0xff;
	frm->flags = frame_head[4]&0xff;
	frm->stream_id = cton(frame_head+5, 31);
	frm->conn = conn;
	//~ frm->payload = NULL;
	frm->request = NULL;
	frm->dpnd_id = 0;
	frm->weight = 0;
	frm->next_id = 0;
	frm->prev_id = 0;
    frm->recv_window = SETTINGS_INITIAL_WINDOW_SIZE;
	//~ frm->recv_window=conn->client_initial_window_size;
    frm->send_window = conn->client_initial_window_size;
	//~ printf("H2_Frame_init: %d\n", frm->send_window);
	
	if (frm->len > 0 && frm->len <= conn->frame_payload.len)
	{
		//~ while ((count = H2_req_read(conn, frm->payload, frm->len)) < frm->len) {}
		H2_req_read(conn, conn->frame_payload.buff, frm->len);
	}
	
	return frm;
}

char *H2_Frame_type(char type) { // just for printf
	switch (type)
	{
		case 0x00:
			return "DATA";
		case 0x01:
			return "HEADERS";
		case 0x02:
			return "PRIORITY";
		case 0x03:
			return "RST_STREAM";
		case 0x04:
			return "SETTINGS";
		case 0x05:
			return "PUSH_PROMISE";
		case 0x06:
			return "PING";
		case 0x07:
			return "GOAWAY";
		case 0x08:
			return "WINDOW_UPDATE";
		case 0x09:
			return "CONTINUATION";
		case 0x0a:
			return "ALTSVC";
		case 0x0b: // Unassigned, used localy
			return "UNIX_SOCKET";
		case 0x0c:
			return "ORIGIN";
		case 0x10:
			return "PRIORITY_UPDATE";
		default:
			return "unknown frame Type";
	}
}

int H2_thread(void *arg) {
	
	struct H2_connection *conn;
    struct H2_Frame *frm = NULL;
	int count=0;
	int i=0, t=0, h=0, weight=0, size=0, t_size=0;
	//~ int weight_size = 255;
	char frame_head[9];
	struct buffer *data_save;

	struct epoll_event ev; // for return the connection after one shot on epoll
	
	while (!mtx_lock(&conn_role_mutex)) {
		conn = thread_conn_role;
		mtx_unlock(&new_conn_mutex);
		
		while (conn)
		{
			//~ printf("fd: %d\n",conn->fd);
			i=0;
			count = H2_req_read(conn, frame_head, 9);
			//~ printf("count: %d\n",count);
			if (count!=9) // response other requests
			{
				if (count == 0) {
					//~ printf("client disconected\n");
					free_connection(conn);
					conn = NULL;
					break;
				}
				else if (conn->frm_id>0 && conn->stream_id[conn->frm_id] && conn->stream_id[conn->frm_id]->request)
				{
					if (conn->stream_id[conn->frm_id]->request->file.fd==0) // if there is no file
					{
						H2_reset_stream(conn, conn->frm_id);
						continue;
					}
					
					h = conn->frm_id;
					t=0;
					weight=-1;

					while (t<255) // send only 245 frame or less then break the loop and check if there is comming frames
					{
						t++;
						weight++; // for concurrency for each stream
						
						if (weight > conn->stream_id[h]->weight) 
						{
							weight=0;
							h = conn->stream_id[h]->next_id;
							if (h==0){break;}
						}
						
						if (conn->stream_id[h]->send_window <= 0)
						{
							H2_reset_stream(conn, h); // to prevent infinit loop
							//~ printf("t: %d\n",t);
							break;
						}
						
						t_size = (conn->stream_id[h]->send_window-10000>0?10000:conn->stream_id[h]->send_window);
						size = read(conn->stream_id[h]->request->file.fd, conn->frame_payload.buff, t_size);
						
						//~ printf("________%d_%d__\n",t_size, size);
						
						conn->send_window-=size; // The connection flow-control window
						conn->stream_id[h]->send_window-=size; // stream flow-control window
						
						if (size == 0)
						{
							H2_reset_stream(conn, h);
							break;
						} 
						else if(size < t_size)
						{
							H2_res_write(conn, size, 0, 1, h, conn->frame_payload.buff);
							H2_res_write(conn, 4, 3, 0, h, "0000"); // send RST_STREAM frame
							H2_free_stream(conn, h);
							break;
						}
						else if (size != H2_res_write(conn, size, 0, 0, h, conn->frame_payload.buff))
						{
							free_connection(conn);
							break;
						}
					}
				}
				else
				{
					//~ printf("\n_________________thread release___________________\n");
					ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
					ev.data.fd = conn->fd;
					epoll_ctl(epollfd, EPOLL_CTL_MOD, conn->fd, &ev);
					//~ sleep(10000);
					//~ shutdown(conn->fd, SHUT_WR);
					//~ sendto(dgram_socket, secret_message, strlen(secret_message)+1, 0,  (struct sockaddr*)&dest, sizeof dest);
					//~ fcntl(conn->fd, F_NOTIFY, DN_MODIFY|DN_CREATE|DN_DELETE|DN_MULTISHOT);
					//~ printf("connection %d\n", i);
					break;
				}
				
				continue;
			}
			
			// fprintf 
			printf("\n");
			printf("____Length: %d___\n", cton(frame_head, 24));
			printf("____Type: %d : %s\n", frame_head[3], H2_Frame_type(frame_head[3]));
			printf("____Flags: %b___\n", frame_head[4]);
			printf("_StreamID: %d___ \n", cton(frame_head+5, 31));
			printf("\n");
			
			if (cton(frame_head+5, 31)>=MAX_CONCURRENT_STREAMS)
			{
				//~ printf("err MAX_CONCURRENT_STREAMS %d\n", cton(frame_head+5, 31));
				H2_res_write(conn, 8, 7, 0, 0, "00000001"); // GOAWAY
				free_connection(conn);
				//~ exit(123123);
				break;
			}
			
			//~ if (cton(frame_head, 24)==0){continue;}
			
			switch (frame_head[3])
			{
				case 0x00: // DATA frame 
				
					//~ i = cton(buffer+5, 31); // stream_id 
					frm = conn->stream_id[cton(frame_head+5, 31)];
					//~ header = get_header(frm, conn->dynamic_table, "content-length"); // frm->request->headers
					
					if (cton(frame_head, 24) == 0)
					{
						break;
					}
					//~ else if (!frm)
					//~ {
						//~ if (cton(frame_head, 24) > conn->/*16KB*/client_max_frame_size)
						//~ {
							//~ H2_res_write(conn, 8, 7, 0, 0, "00000001"); // GOAWAY
							//~ free_connection(conn);
							//~ break;
						//~ }
						
						//~ H2_req_read(conn, conn->frame_payload.buff, cton(frame_head, 24)); //remove data from buffer
					//~ }
					else if (frm && frm->request && cton(frame_head, 24) <= conn->/*16KB*/client_max_frame_size)
					{
						//adjust the recive window :
						frm->recv_window-=cton(frame_head, 24);
						conn->recv_window-=cton(frame_head, 24);
						
						//~ printf("_______recv_window_____%d____%d__\n", conn->recv_window, frm->recv_window);
						
						if(frm->recv_window <= MINIMUM_WINDOW_SIZE)
						{
							H2_res_write(conn, 4, 8, 0, frm->stream_id, ntoc(conn->frame_payload.buff, MAXIMUM_WINDOW_UPDATE-frm->recv_window, 31));
							frm->recv_window = MAXIMUM_WINDOW_UPDATE-frm->recv_window;
						}
						
						if (conn->recv_window <= MINIMUM_WINDOW_SIZE)
						{
							H2_res_write(conn, 4, 8, 0, 0, ntoc(conn->frame_payload.buff, MAXIMUM_WINDOW_UPDATE-conn->recv_window, 31));
							conn->recv_window = MAXIMUM_WINDOW_UPDATE-conn->recv_window;
						}
						
						// we are going to re purpose the frm 
						frm->len = cton(frame_head, 24);
						frm->type = frame_head[3];
						frm->flags = frame_head[4];
						// frm->stream_id is the same
						
						if (frm->request->file.fd == 0) // not a FILE 
						{
							if (H2_req_read(conn, conn->frame_payload.buff, frm->len) != frm->len)
							{
								H2_res_writeHead(frm, (array{{NULL,13},{NULL,0} }));
								response_end(frm, "404 Not Found", -1);
								break;
							}
							
							data_save = frm->request->chunk_struct;
							if (!data_save)
							{
								data_save = malloc(sizeof(struct buffer));
								data_save->next = NULL;
								frm->request->chunk_struct = data_save;
							}
							else
							{
								i=0;
								while (data_save->next)
								{
									i++;
									data_save = data_save->next;
								}
								
								if (i>6)
								{
									H2_res_write(conn, 8, 7, 0, 0, "00000001"); // GOAWAY
									free_connection(conn);
									break;
								}
								
								data_save->next = malloc(sizeof(struct buffer));
								data_save = data_save->next;
								data_save->next = NULL;
							}
							
							data_save->buff = malloc(sizeof(char)*cton(frame_head, 24));
							strncpy(data_save->buff, conn->frame_payload.buff+BitVal(frame_head[5], 3), cton(frame_head, 24)-(BitVal(frame_head[5],3)?cton(conn->frame_payload.buff, 8):0));
							data_save->len = cton(frame_head, 24)-(BitVal(frame_head[5],3)?cton(conn->frame_payload.buff, 8):0);
							if (BitVal(frame_head[4],0)==1) // last frame 
							{
								if (frm->request->application)
								{
									frm->request->application(frm);
								}
							}
						}
						else if (frm->request->application) // FILE
						{
							frm->request->application(frm);
						}
						else
						{
							H2_res_writeHead(frm, (array{{NULL,13},{NULL,0} }));
							response_end(frm, "404 Not Found", -1);
							break;
						}
					}
					else
					{
						//~ printf("frame size error\n");
						H2_res_write(conn, 8, 7, 0, 0, "00000001"); // GOAWAY
						free_connection(conn);
						break;
					}
				break;
				case 0x01: // HEADERS frame
					frm = H2_Frame_init(conn, frame_head);
					conn->stream_id[frm->stream_id] = frm; // add it to connection struct
					printf("headers parseing ...\n");
					
					frm->request = H2_parse_headers(frm, conn);
					
					if(conn->dynamic_table_len > MAX_HEADER_LIST_SIZE) {
						H2_res_write(conn, 8, 7, 0, 0, "00000001"); // GOAWAY
						free_connection(conn);
						break;
					}
					
					//fprintf
					printf("method: '%.*s'\n", frm->request->method.len, frm->request->method.buff);
					printf("authority: '%.*s'\n", conn->authority.len, conn->authority.buff);
					printf("path: '%.*s'\n", frm->request->path.len, frm->request->path.buff);
										
					if (!strncmp("GET", frm->request->method.buff, frm->request->method.len))
					{
						H2_add_Frame(conn, frm);
					}
					
					if (frm->request->application)
					{
						frm->request->application(frm);
					}
					else
					{
						H2_res_writeHead(frm, (array{{NULL,13},{NULL,0} }));
						response_end(frm, "<h1>404 Not Found</h1>", -1);
					}
					
				break;
				case 0x02: // PRIORITY frame // The PRIORITY frame (type=0x02) is deprecated;
				
					//~ if (cton(buffer, 24) > 0 && cton(buffer, 24) < 100)
					//~ H2_req_read(conn, data, cton(buffer, 24));
					frm = H2_Frame_init(conn, frame_head);
					conn->stream_id[frm->stream_id] = frm;
					//~ printf("____Exclusive: %d \n", BitVal(conn->frame_payload.buff[0], 7));
					//~ printf("____Stream_Dependency: %d \n", cton(conn->frame_payload.buff, 31));
					frm->dpnd_id = cton(conn->frame_payload.buff, 31);
					//~ printf("____Weight: %d \n", cton(conn->frame_payload.buff+4, 8));
					frm->weight = conn->frame_payload.buff[4]&0xff;
					//~ frm->len-=5;
					
				break;
				case 0x04: // SETTINGS frame
					if (BitVal(frame_head[4],0)==1) break;
					
					i=H2_req_read(conn, conn->frame_payload.buff, cton(frame_head, 24));
					H2_parse_settings(conn, conn->frame_payload.buff, i);
					
					H2_res_write(conn, 30, 4, 0, 0,
						"\x00\x01\x00\x00\x10\x00"
						"\x00\x03\x00\x00\x00\x64"
						"\x00\x04\x00\x00\xFF\xFF"
						"\x00\x05\x00\x00\x40\x00"
						"\x00\x06\x00\x00\x00\xFF"
					);
					
					H2_res_write(conn, 0, 4, 1, 0, NULL); // SETTINGS ack
										
					//~ 1-SETTINGS_HEADER_TABLE_SIZE (0x01):
					//~ 2-SETTINGS_ENABLE_PUSH (0x02): /* \x00\x02\x00\x00\x00\x00\*/ push is deprecated;
					//~ 3-SETTINGS_MAX_CONCURRENT_STREAMS (0x03):
					
					//~ 4-SETTINGS_INITIAL_WINDOW_SIZE (0x04):
					
					//~ 5-SETTINGS_MAX_FRAME_SIZE (0x05):
					//~ 6-SETTINGS_MAX_HEADER_LIST_SIZE (0x06):
					
					//~ 7-SETTINGS_MINIMUM_WINDOW_SIZE(0x7)
					//~ 8-SETTINGS_MINIMUM_WINDOW_UPDATE(0x8)
					
					// firefox client setting frame
					//~ _00_01 _00_01_00_00
					//~ _00_02 _00_00_00_00
					//~ _00_04 _00_02_00_00
					//~ _00_05 _00_00_40_00
					
					// samsung internet client setting frame
					//~ _00_01 _00_01_00_00
					//~ _00_02 _00_00_00_00
					//~ _00_04 _00_60_00_00
					//~ _00_06 _00_04_00_00
					
					//~ web gnome project
					//~ _00_04 _00_60_00_00
					//~ _00_01 _00_01_00_00
					//~ _00_02 _00_00_00_00
				break;
				case 0x06: // PING frame
					H2_req_read(conn, conn->frame_payload.buff, cton(frame_head, 24));
					H2_res_write(conn, 8, 6, 1, 0, conn->frame_payload.buff);
				break;
				case 0x08: // WINDOW_UPDATE frame
					H2_req_read(conn, conn->frame_payload.buff, cton(frame_head, 24));
					//~ printf(" + %d\n",cton(frame_head+9, 31));
					if (cton(frame_head+5, 31)==0)
					{
						conn->send_window += cton(conn->frame_payload.buff, 31);
					}
					else if (conn->stream_id[cton(frame_head+5, 31)])
					{
						frm = conn->stream_id[cton(frame_head+5, 31)];
						frm->send_window += cton(conn->frame_payload.buff, 31);
						
						if (!strncmp("GET", frm->request->method.buff, frm->request->method.len))
						{
							H2_add_Frame(conn, frm);
						}
					}
				break;
				case 0x0b: // UNIX domain sockets frame, not rfc frame
					i=cton(frame_head+5, 31); //StreamID
					//~ conn_save = get_conn_list(i);
					
					//~ if (!conn_save || (count = H2_req_read(conn, frame_head+9, cton(frame_head, 24)))<=0)
					//~ {
						 //~ // H2_res_write(conn, 4, 3, 0, frm->stream_id, "0000");
						 //~ H2_free_stream(conn, frm->stream_id);
						 //~ return NULL;
					//~ }
					
					//~ H2_res_write(conn_save, count, 0, 0, conn_save->event_frm_id, frame_head+9);	
				break;
				case 0x03: // RST_STREAM frame _00_00_00_08
					H2_free_stream(conn, cton(frame_head+5, 31));
				break;
				case 0x07: // GOAWAY frame
					free_connection(conn);
				break;
				case 0x05: // PUSH_PROMISE frame
				case 0x09: // CONTINUATION frame
				case 0x10: // PRIORITY_UPDATE frame
				//~ break;
				default:  // Type error frame
					printf("___________Type error\n");
					if (cton(frame_head, 24) > 0 && cton(frame_head, 24) < 1000)
					{
						H2_req_read(conn, conn->frame_payload.buff, cton(frame_head, 24));
						for (i = 0; i < cton(frame_head, 24); i++) {
							printf("_%02x", (unsigned)(conn->frame_payload.buff)[i] & 0xFF);
							//~ printf("_%c", (unsigned)(frame_head+9)[i]);
						}
					}
					
					H2_res_write(conn, 8, 7, 0, 0, "00000001"); // GOAWAY, protocol erorr
					free_connection(conn);
					break;
			}
			
			//~ printf(" next \n");
		}
	}
	
	//~ OPENSSL_thread_stop();
	//~ BIO_free_all(SSL_get_rbio(conn->ssl));
	
	//~ OPENSSL_thread_stop();
	//~ OPENSSL_cleanup();
	return 0;
}

struct buffer *H2_getfrom_dynamic_table(char *dynamic_table, char *buffer, int len) {
	
	return NULL;
}






