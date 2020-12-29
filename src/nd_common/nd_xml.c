/* file nd_xml.c
 * implement xml parser of nd engine 
 * version 1.0 
 * 2008-8-24 
 * all right reserved by duan xiuyun 
 */

#include "nd_common/nd_common.h"
#include "nd_common/nd_iconv.h"

#include <stdlib.h>
#include <stdio.h>

//#define MAX_FILE_SIZE 4*4096
#define XML_H_END   0x3e2f			// /> xml node end mark
#define XML_T_END   0x2f3c			// </ xml end node mark,big end  >
//static int  _is_mark_end(const char *p)
//{
//	if (*p == 0x2f && *(p+1)=='>') {
//		return 1;
//	}
//	return 0;
//}
//
//static int  _is_mark_start(const char *p)
//{
//	if (*p == '<' && *(p+1)==0x2f) {
//		return 1;
//	}
//	return 0;
//}

static int _s_replace_key_word = 1;

int ndxml_open_keyword_replace(int enable)
{
	int ret = _s_replace_key_word;
	_s_replace_key_word = enable;
	return ret;
}


static const char* _read_replace_text(const char *src, char *outText)
{
	const char *p = src;
	char buf[16];
	if (*p++ != '&')	{
		return src;
	}
	
	buf[0] = 0;
	p = ndstr_nstr_ansi(p, buf, ';', sizeof(buf)-1);
	if (*p != ';')	{
		*outText = *src;
		return src +1;
	}
	++p;

	if (0 == ndstricmp(buf, "amp")) {
		*outText = '&';
	}
	else if (0 == ndstricmp(buf, "lt")) {
		*outText = '<';
	}
	else if (0 == ndstricmp(buf, "gt")) {
		*outText = '>';
	}
	else if (0 == ndstricmp(buf, "quot")) {
		*outText = _ND_QUOT;
	}
	else if (0 == ndstricmp(buf, "apos")) {
		*outText = _ND_SINGLE_QUOT;
	}
	else if (0 == ndstricmp(buf, "nbsp")) {
		*outText = ' ';
	}
	else if (0 == ndstricmp(buf, "times")) {
		*outText = '*';
	}
	else if (0 == ndstricmp(buf, "divde")) {
		*outText = '/';
	}
// 	else if (0 == ndstricmp(buf, "bsc")) {
// 		*outText = '\\';
// 	}
	else {
		nd_assert(0);
		//return src;
	}
	return p;
}


static const char* _out_replace_text(const char *src, char *outText,size_t len)
{
	const char *p = src;	
	char *ret = outText;
	int buf_size = (int)len;

	if (_s_replace_key_word == 0) {
		return src;
	}

	*outText = 0;

	while (*p && buf_size > 0){
		
		if (*p == _ND_SINGLE_QUOT){
			ndstrncat(outText, "&apos;", buf_size);
			outText += 6;
			buf_size -= 6;
			++p;
		}
		else if (*p == _ND_QUOT) {
			ndstrncat(outText, "&quot;", buf_size);
			outText += 6;
			buf_size -= 6;
			++p;
		}

		else if (*p == ' ') {
			ndstrncat(outText, "&nbsp;", buf_size);
			outText += 6;
			buf_size -= 6;
			++p;
		}
		else if (*p == '&') {
			ndstrncat(outText, "&amp;", buf_size);
			outText += 5;
			buf_size -= 5;
			++p;
		}
		else if (*p == '*') {
			ndstrncat(outText, "&times;", buf_size);
			outText += 7;
			buf_size -= 7;
			++p;
		}
		else if (*p == '/') {
			ndstrncat(outText, "&divde;", buf_size);
			outText += 7;
			buf_size -= 7;
			++p;
		}

		else if (*p == '<') {
			ndstrncat(outText, "&lt;", buf_size);
			outText += 4;
			buf_size -= 4;
			++p;
		}

		else if (*p == '>') {

			ndstrncat(outText, "&gt;", buf_size);
			outText += 4;
			buf_size -= 4;
			++p;
		}
		else {

			int ret = ndstr_read_utf8char((char **)&p, (char**)&outText);
			buf_size -= ret;
			*outText = 0;
		}
	}
	*outText = 0;
	nd_assert(buf_size >= 0);

	return ret;

}

static size_t _stream_to_file(FILE *pf, const char *stm, ...)
{
	size_t size,ret;
	char buf[0x10000];
	char *p = buf;
	va_list arg;
	int done;

	size = sizeof(buf);
	ret = 0;

	va_start(arg, stm);
	done = ndvsnprintf(p, size, stm, arg);
	size -= done;
	ret += done;
	va_end(arg);
	
	return fwrite(buf, 1, ret, pf);
}


static const char *_xml_read_attrval(const char *xmlbuf, char *buf, size_t size)
{
	const char *p = xmlbuf;
	while (*p != _ND_QUOT){
		if (!*p) {
			return NULL;
		}
		if (*p == '>'){
			return NULL;
		}
		++p;
	}
	++p; //skip "

	while (*p && size > 0){
		if (*p == _ND_QUOT) {
			++p;
			break;
		}
		else if (*p == '&' && (IS_LITTLE_LATIN(p[1]) || IS_BIG_LATIN(p[1]))) {
			p = _read_replace_text(p, buf);
			if (!p)	{
				return NULL;
			}
			++buf;
			--size;
		}
		else {
			int ret = ndstr_read_utf8char((char **)&p, (char**)&buf);
			if (size < ret)	{
				return NULL;
			}
			size -= ret;
		}
	}
	*buf = 0;
	return p;
}

static const char *_xml_read_value(const char *xmlbuf, char *buf, size_t size)
{
	const char *p = xmlbuf;

	while (*p && size > 0){
		if (*p == '&' && (IS_LITTLE_LATIN(p[1]) || IS_BIG_LATIN(p[1]))){
			p = _read_replace_text(p, buf);
			++buf;
			--size;
		}
		else if (*p == '<' && *(p+1)=='/') {
			break;
		}
		else {
			int ret = ndstr_read_utf8char((char **)&p, (char**)&buf);
			size -= ret;
		}
	}
	*buf = 0;
	return p;
}

static size_t _xml_get_value_size(const char *p)
{
	size_t ret = 0;
	char buf[10];
	while (*p) {
		
		if (*p == '&' && (IS_LITTLE_LATIN(p[1]) || IS_BIG_LATIN(p[1]))) {
			p = _read_replace_text(p, buf);
			++ret;
		}
		else if (*p == '<' && *(p + 1) == '/') {
			break;
		}
		else {
			char *pOut = buf;
			int len = ndstr_read_utf8char((char **)&p, (char**)&pOut);
			ret += len;
		}
	}
	return ret;
}

ndxml *parse_xmlbuf(const char *xmlbuf, int size, const char **parse_end, const char **error_addr) ;
ndxml *alloc_xml(void);
void _release_xml(ndxml *node);
void  dealloc_xml(ndxml *node );
struct ndxml_attr *alloc_attrib_node(const char *name, const char *value);
void dealloc_attrib_node(struct ndxml_attr *pnode);
int xml_write(ndxml *xmlnode, FILE *fp , int deep) ;
ndxml *_create_xmlnode(const char *name, const char *value)  ;

static int _errlog (const char *errdesc) ;
static void show_xmlerror(const char *file, const char *error_addr, const char *xmlbuf, size_t size) ;

static int xml_parse_fileinfo(ndxml_root *xmlroot, char *start, char **endaddr, char **erraddr);

static int xml_set_code_type(ndxml_root *xmlroot);
static xml_errlog __xml_logfunc = _errlog ;


int xml_load_from_buf(const char *buf, size_t size, ndxml_root *xmlroot,const char *filename)
{
	int data_len = (int)size;
	const char *parse_addr =  buf;
	const char *error_addr = 0;
	do {
		parse_addr = ndstr_first_valid(parse_addr) ;
		if (parse_addr) {
			ndxml *xmlnode = parse_xmlbuf(parse_addr, data_len, &parse_addr, &error_addr);
			if (xmlnode) {
				list_add_tail(&xmlnode->lst_self, &xmlroot->lst_sub);
				xmlnode->parent = xmlroot;
				xmlroot->sub_num++;
			}
			else if (error_addr) {
				ndxml_destroy(xmlroot);
				show_xmlerror(filename, error_addr, buf, (size_t)data_len);
				return -1;
			}
		}
		
	} while (parse_addr && *parse_addr);

	return 0;
}

int ndxml_load_from_buf(const char *fileName, const char *buf, size_t size, ndxml_root *xmlroot, const char *toEncodeType)
{
	int codeType = -1;
	int ret = 0;
	
	char *pAddr, *pErrorAddr = 0;
	char *pTextEncode = 0;
	char*pBuf = (char*)buf;
	char *pconvertbuf = NULL;

	//ndxml_root *xmlroot;
	ndxml_initroot(xmlroot);
	if (-1 == xml_parse_fileinfo(xmlroot, pBuf, &pAddr, &pErrorAddr)) {
		ndxml_destroy(xmlroot);
		return -1;
	}

	pTextEncode = (char*) ndxml_getattr_val(xmlroot, "encoding");
	if (pTextEncode && *pTextEncode){
		if (toEncodeType && toEncodeType[0]) {
			int nTextType = nd_get_encode_val(pTextEncode);
			int nNeedType = nd_get_encode_val(toEncodeType);

			nd_code_convert_func func = nd_get_code_convert(nTextType, nNeedType);

			if (func){
				char *pconvertbuf = malloc(size * 2);
				if (!pconvertbuf)	{
					return -1;
				}
				if (func(pBuf, pconvertbuf, (int)size * 2)) {
					pBuf = pconvertbuf;
					size = ndstrlen(pconvertbuf);
				}
				else {
					free(pconvertbuf);
					nd_logerror("convert text econde from %s to %s \n", pTextEncode, toEncodeType);
					return -1;
				}
				ndxml_setattrval(xmlroot, "encoding", toEncodeType);
			}
			if (nNeedType != ndstr_get_code()) {
				codeType = ndstr_set_code(nNeedType);
			}
		}
		else {
			codeType = xml_set_code_type(xmlroot);
		}
	}


	if (-1 == xml_load_from_buf(pBuf, size, xmlroot, fileName)) {
		ret = -1;
	}

	if (codeType != -1) {
		ndstr_set_code(codeType);
	}
	if (pconvertbuf) {
		free(pconvertbuf);
	}

	return ret;
}
int ndxml_load(const char *file,ndxml_root *xmlroot)
{
	return ndxml_load_ex(file, xmlroot, NULL);	
}


int ndxml_is_empty(ndxml *node)
{
	if (node->name[0] == 0 && list_empty(&node->lst_sub) && list_empty(&node->lst_attr)) {
		return 1;
	}
	return 0;
}

int ndxml_load_ex(const char *file, ndxml_root *xmlroot, const char*encodeType)
{
	size_t size = 0;
	char*pBuf = nd_load_file(file, &size);
	if (!pBuf){
		nd_logerror("load file %s error\n", file);
		return -1;
	}
	int ret = ndxml_load_from_buf(file, pBuf, size, xmlroot, encodeType);

	nd_unload_file(pBuf);
	return ret;

}

void ndxml_destroy(ndxml_root *xmlroot)
{

	_release_xml(xmlroot);
	ndxml_initroot(xmlroot) ;
}

int xml_set_code_type(ndxml_root *xmlroot)
{
	int oldType = -1;
	const char *p = ndxml_getattr_val(xmlroot, "encoding");
	if (p){
		oldType = nd_get_encode_val(p);

		oldType = ndstr_set_code(oldType);
	}
	return oldType;
}
int xml_parse_fileinfo(ndxml_root *xmlroot, char *start, char **endaddr, char **erraddr)
{
	const char *p = start;
	const char *pEnd;
	
	*endaddr = start;

	p = ndstr_first_valid(p);
	if (!p){
		*erraddr = start;
		return -1;
	}
	
	p = ndstrstr(p, "<?");
	if (!p){
		return 0;
	}

	p = ndstrstr(p, "xml");
	if (!p){
		return 0;
	}
	p += 3;

	pEnd = ndstrstr(p, "?>");
	if (!pEnd){
		*endaddr =(char*) p;
		*erraddr = (char*)p;
		return -1;
	}

	//parse attribute 
	while (p < pEnd) {
		struct ndxml_attr *attrib_node;
		char attr_name[MAX_XMLNAME_SIZE];
		char valbuf[1024];

		p = ndstr_first_valid(p);
		*endaddr = (char*)p;
		*erraddr = start;
		
		attr_name[0] = 0;
		p = ndstr_parse_word_n(p, attr_name,sizeof(attr_name));
		if (attr_name[0] == 0)	{
			break;
		}
		p = ndstrchr(p, _ND_QUOT);
		if (!p) {
			return -1;
		}
		++p;
		//read attrib VALUE
		valbuf[0] = 0;
		p = ndstr_str_end(p, valbuf, _ND_QUOT);
		++p;

		attrib_node = alloc_attrib_node(attr_name, valbuf);
		if (attrib_node) {
			list_add_tail(&attrib_node->lst, &xmlroot->lst_attr);
			(xmlroot->attr_num)++;
		}
	}


	*endaddr = (char*)pEnd + 2;
	*erraddr = 0;
	return 0;

}
//显示xml错误
void show_xmlerror(const char *file, const char *error_addr, const char *xmlbuf, size_t size)
{
	int line = 0 ;
	const char *pline, *pnext ;
	char errbuf[1024] ;

	errbuf[0] = 0 ;
	pline = xmlbuf ;

	//pnext = pline ;

	while (pline<xmlbuf+size) {
		//pline = pnext ;
		pnext = ndstrchr(pline, '\n') ;
		if(!pnext) {
			ndsnprintf(errbuf, 1024, "know error in file %s  line %d", file, line) ;
			break ;				
		}
		//pnext  ;
		++line ;
		if(error_addr>=pline && error_addr< pnext) {
			pline = ndstr_first_valid(pline) ;
			ndsnprintf(errbuf, 1024, "parse error in file %s  line %d \n", file, line) ;
			break ;				
		}
		pline = ++pnext ;
	}
	
	if(__xml_logfunc && errbuf[0]) {
		__xml_logfunc(errbuf) ;
	}
	return ;
}

 xml_errlog nd_setxml_log(xml_errlog logfunc) 
 {
	 xml_errlog ret =  __xml_logfunc ;
	 __xml_logfunc = logfunc ;
	 return ret ;
 }

int ndxml_save_ex(ndxml_root *xmlroot, const char *file,const char*header)
{
    FILE *fp;
    ndxml *sub_xml;
	struct list_head *pos = xmlroot->lst_sub.next;
#ifdef __ND_WIN__
    fp = fopen(file, "wb") ;
#else 
	fp = fopen(file, "w");
#endif
	if (!fp) {
		//nd_logerror("open file %s : %s\n", file, nd_last_error());
        return -1;
    }
    if (header && header[0]) {
		_stream_to_file(fp, "<?xml %s ?>\n", header) ;

    }
    
	while (pos != &xmlroot->lst_sub) {
        sub_xml = list_entry(pos,struct tagxml, lst_self) ;
        pos = pos->next ;
        xml_write(sub_xml,fp, 0) ;
        
    }
    
	fflush(fp);
    fclose(fp) ;
    
    return 0;
    
}

int ndxml_save(ndxml_root *xmlroot, const char *file)
{
	char buf[4096];
	struct list_head *pos;
	int size = 0;
	char *p = buf;
	int bufsize = sizeof(buf);

	buf[0] = 0;
	//save attribute to file 
	pos = xmlroot->lst_attr.next;
	while (pos != &xmlroot->lst_attr){
		struct ndxml_attr *xml_attr = list_entry(pos, struct ndxml_attr, lst);
		char *attr_val1 = (char*)(xml_attr + 1) + xml_attr->name_size;
		pos = pos->next;
		if (attr_val1[0]) {
			size = ndsnprintf(p, bufsize, " %s=\"%s\"", (char*)(xml_attr + 1), attr_val1);
			bufsize -= size;
			p += size;
		}
		else {
			size =  ndsnprintf(p, bufsize, " %s=\"\"", (char*)(xml_attr + 1));
			bufsize -= size;
			p += size;
		}
	}
	if (buf[0] == 0){
#if defined(ND_GB2312)  || defined(ND_GBK)
		ndsnprintf(p, bufsize, "version=\"1.0\" encoding=\"GBK\"");
#elif defined(ND_UTF_8)
		ndsnprintf(p, bufsize, "version=\"1.0\" encoding=\"utf-8\"");
#else 
		ndsnprintf(p, bufsize, "version=\"1.0\" encoding=\"ANSI\"");
#endif
	}
    return ndxml_save_ex(xmlroot, file, buf) ;
}


int ndxml_save_encode(ndxml_root *xmlroot, const char *file, int inputCode, int outputCode)
{
	char buf[128];
	buf[0] = 0;
	
	if (outputCode == E_SRC_CODE_GBK){
		ndsnprintf(buf, sizeof(buf), "version=\"1.0\" encoding=\"GBK\"");
	}
	else if (outputCode == E_SRC_CODE_UTF_8){
		ndsnprintf(buf, sizeof(buf), "version=\"1.0\" encoding=\"utf-8\"");
	}
	else {
		ndsnprintf(buf, sizeof(buf), "version=\"1.0\" encoding=\"ANSI\"");
	}

		
	int ret = ndxml_save_ex(xmlroot, file, buf); 
	nd_code_convert_func func = nd_get_code_convert(inputCode, outputCode);

	if (func){
		return nd_code_convert_file(file, inputCode, outputCode);
	}
	return ret;
}

ndxml *ndxml_copy(ndxml *node)
{
	int i;
	ndxml *newnode = NULL ;
	
	if (!node) {
		return NULL;
	}
	
	newnode = _create_xmlnode(node->name, node->value) ;
	
	for (i=0; i<ndxml_getattr_num(node); ++i) {
		ndxml_addattrib(newnode, ndxml_getattr_name(node, i), ndxml_getattr_vali(node, i)) ;
	}
	for (i=0; i<ndxml_getsub_num(node); ++i) {
		ndxml *sub1 = ndxml_refsubi(node, i);
		ndxml *sub_new = ndxml_copy(sub1);
		if (sub_new) {
			list_add_tail(&sub_new->lst_self, &newnode->lst_sub) ;
			sub_new->parent = newnode;
			newnode->sub_num++;
		}
	}
	return newnode ;
}

int ndxml_insert(ndxml *parent, ndxml*child)
{
	list_add_tail(&child->lst_self, &parent->lst_sub);
	child->parent = parent;
	parent->sub_num++;
	return 0;
}

int ndxml_get_myindex(ndxml*xml)
{
	ndxml *parent =ndxml_get_parent(xml);
	if (parent == NULL) {
		return -1;
	}
	return ndxml_get_index(parent, xml);
}

int ndxml_get_index(ndxml *parent, ndxml*child)
{
	int i = 0;
	struct list_head *pos;
	list_for_each(pos, &parent->lst_sub) {
		if (pos == &(child->lst_self)) {
			return i;
		}
		++i;
	}
	return -1;
}

int ndxml_insert_ex(ndxml *parent, ndxml*child, int index)
{
	int i = 0;
	if (index != -1)	{
		struct list_head *pos;
		list_for_each(pos, &parent->lst_sub) {
			if (index <= i)	{
				list_add(&child->lst_self, pos);
				parent->sub_num++;
				return 0;
			}
			++i;
		}
	}

	list_add_tail(&child->lst_self, &parent->lst_sub);
	child->parent = parent;
	parent->sub_num++;
	return 0;	
}


int ndxml_insert_after(ndxml *parent, ndxml*insertNode, ndxml* brother)
{
	if (brother == parent){
		list_add(&insertNode->lst_self, &parent->lst_sub);
	}

	else if (brother->parent != parent){
		return -1;
	}
	else {
		list_add(&insertNode->lst_self, &brother->lst_self);
	}

	insertNode->parent = parent;
	parent->sub_num++;
	return 0;


}
int ndxml_insert_before(ndxml *parent, ndxml*insertNode, ndxml*brother)
{
	if (brother == parent){
		list_add_tail(&insertNode->lst_self, &parent->lst_sub);
	}

	else if (brother->parent != parent){
		return -1;
	}
	else {
		list_add_tail(&insertNode->lst_self, &brother->lst_self);
	}

	insertNode->parent = parent;
	parent->sub_num++;
	return 0;

}

int ndxml_merge(ndxml_root *host, ndxml_root *merged) 
{
	if(merged->sub_num > 0) {
		list_join(&merged->lst_sub, &host->lst_sub);
		host->sub_num += merged->sub_num ;

		ndxml_initroot(merged);
	}
	return 0 ;
}

ndxml *ndxml_getnode(ndxml_root *xmlroot,const  char *name)
{
	ndxml *sub_xml; 
	struct list_head *pos = xmlroot->lst_sub.next;
	while (pos != &xmlroot->lst_sub) {
		sub_xml = list_entry(pos,struct tagxml, lst_self) ;
		pos = pos->next ;
		if (0==ndstricmp((char*)name,sub_xml->name)){
			return sub_xml ;
		}
	}
	return NULL ;
}
ndxml *ndxml_getnodei(ndxml_root *xmlroot, int index) 
{
	int i = 0 ;
	ndxml *sub_xml; 
	struct list_head *pos = xmlroot->lst_sub.next;

	while (pos != &xmlroot->lst_sub) {
		sub_xml = list_entry(pos,struct tagxml, lst_self) ;
		pos = pos->next ;
		if(i==index){
			return sub_xml ;
		}
		++i ;
	}
	return NULL ;
}

ndxml *ndxml_addnode(ndxml_root *xmlroot, const char *name,const char *value)
{
	ndxml *xmlnode = _create_xmlnode(name, value) ;
	if(xmlnode){
		list_add_tail(&xmlnode->lst_self, &xmlroot->lst_sub);
		xmlnode->parent = xmlroot;

		xmlroot->sub_num++ ;
	}
	return xmlnode ;
}


ndxml* ndxml_big_brother(ndxml *node)
{
	struct list_head *prev = node->lst_self.prev;
	ndxml *parent = node->parent;
	if (!parent){
		return NULL;
	}
	if (prev != &parent->lst_sub) {
		return list_entry(prev, struct tagxml, lst_self);
	}
	return NULL;
}
ndxml* ndxml_little_brother(ndxml *node)
{
	struct list_head *next = node->lst_self.next;
	ndxml *parent = node->parent;
	if (!parent){
		return NULL;
	}
	if (next != &parent->lst_sub) {
		return list_entry(next, struct tagxml, lst_self);
	}
	return NULL;
}


ndxml *ndxml_from_text(const char *text)
{
	const char *pend, *perraddr;
	return parse_xmlbuf(text, (int)ndstrlen(text), &pend, &perraddr);
}

int ndxml_delnode(ndxml_root *xmlroot,const  char *name)
{
	ndxml *node = ndxml_getnode(xmlroot,name) ;
	if(!node)
		return -1 ;
	list_del(&node->lst_self) ;
	xmlroot->sub_num-- ;
	dealloc_xml(node);
	return 0 ;
}

int ndxml_delnodei(ndxml_root *xmlroot, int index) 
{
	ndxml *node = ndxml_getnodei(xmlroot,index) ;
	if(!node)
		return -1 ;
	list_del(&node->lst_self) ;
	xmlroot->sub_num-- ;
	dealloc_xml(node);
	return 0 ;
}

void ndxml_delall_children(ndxml* xml)
{
	struct list_head *pos,*next;
	struct list_head *header = &xml->lst_sub;


	list_del_init(&xml->lst_sub);	
	xml->sub_num = 0;

	list_for_each_safe(pos, next, header ) {
		ndxml *sub_xml = list_entry(pos, struct tagxml, lst_self);
		dealloc_xml(sub_xml);
	}
}


void ndxml_delall_attrib(ndxml* xml)
{
	struct list_head *pos, *next;
	struct list_head *header = &xml->lst_attr;


	list_del_init(&xml->lst_attr);
	xml->sub_num = 0;

	list_for_each_safe(pos, next, header) {
		struct ndxml_attr *attrnode = list_entry(pos, struct ndxml_attr, lst);
		dealloc_attrib_node(attrnode);
	}
}

int ndxml_unlink(ndxml *node, ndxml *xmlParent)
{
	int ret = -1;
	struct list_head *pos;

	if (!node)
		return -1;

	if (xmlParent == NULL)	{
		xmlParent = node->parent;
		if (!xmlParent)	{
			list_del_init(&node->lst_self);
			return 0;
		}
	}
	pos = xmlParent->lst_sub.next;
	
	while (pos != &xmlParent->lst_sub) {
		ndxml *sub_xml = list_entry(pos, struct tagxml, lst_self);
		pos = pos->next;
		if (sub_xml == node){
			ret = 0;
			break;
		}

	}
	if (ret == -1)	{
		return ret;
	}
	list_del_init(&node->lst_self);
	node->parent = NULL;
	xmlParent->sub_num--;
	return 0;
}
int ndxml_delxml(ndxml *node, ndxml *xmlParent)
{
	if (!xmlParent) {
		xmlParent = node->parent;
	}

	if (xmlParent)	{
		if (0 == ndxml_remove(node, xmlParent)) {
			dealloc_xml(node);
			return 0;
		}

	}
	else {
		list_del(&node->lst_self);
		dealloc_xml(node);
	}
	return -1;
}


void ndxml_free(ndxml *node)
{
	dealloc_xml(node);
}

//引用一个子节点
ndxml *ndxml_refsub(ndxml *root, const char *name) 
{
	ndxml *sub_xml; 
	struct list_head *pos = root->lst_sub.next ;
	while (pos!=&root->lst_sub) {
		sub_xml = list_entry(pos,struct tagxml, lst_self) ;
		pos = pos->next ;
		if (0==ndstricmp((char*)name,sub_xml->name)){
			return sub_xml ;
		}
	}
	return NULL ;
}

//引用一个子节点
ndxml *ndxml_refsubi(ndxml *root, int index) 
{
	int i = 0 ;
	ndxml *sub_xml; 
	struct list_head *pos = root->lst_sub.next ;

	while (pos!=&root->lst_sub) {
		sub_xml = list_entry(pos,struct tagxml, lst_self) ;
		pos = pos->next ;
		//if (0==ndstricmp(name,sub_xml->name)){
		if(i==index){
			return sub_xml ;
		}
		++i ;
	}
	return NULL ;
}

//得到xml的值
const char *ndxml_getval(ndxml *node)
{
	if (node->value && node->value[0]){
		return node->value;
	}
	else
		return NULL ;
}

char *ndxml_getval_buf(ndxml *node, char *buf, size_t size)
{
	if(node->value && node->value[0])
		return ndstrncpy(buf,node->value, size) ;
	else {
		buf[0] = 0;
		return NULL;
	}
}

int ndxml_getval_int(ndxml *node)
{
	if(node->value && node->value[0])
		return (int)ndstr_atoi_hex(node->value );
	else
		return 0 ;
}

NDINT64 ndxml_getval_int64(ndxml *node)
{
	if (node->value && node->value[0])
		return ndstr_atoll_hex(node->value);
	else
		return 0;
}


float ndxml_getval_float(ndxml *node)
{
	if(node->value && node->value[0])
		return (float)atof(node->value );
	else
		return 0 ;
}
//得到属性值
struct ndxml_attr *ndxml_getattrib(ndxml *node ,const  char *name)
{
	struct ndxml_attr *attr ;
	struct list_head *pos = node->lst_attr.next;
	while (pos!= &node->lst_attr){
		attr = list_entry(pos,struct ndxml_attr, lst) ;
		pos=pos->next ;
		if(0==ndstricmp(name, (char*)(attr+1))) {
			return attr ;
		}
	}
	return NULL ;
}

struct ndxml_attr  *ndxml_getattribi(ndxml *node, int index)
{
	int i=0 ;
	struct ndxml_attr *attr ;
	struct list_head *pos = node->lst_attr.next;
	while (pos!= &node->lst_attr){
		attr = list_entry(pos,struct ndxml_attr, lst) ;
		pos=pos->next ;
		//if(0==ndstricmp(name,attr->name)) {
		if(i==index){
			return attr ;
		}
		++i ;
	}
	return NULL ;

}

//////////////////////////////////////////////////////////////////////////
//给xml增加一个属性,
struct ndxml_attr  *ndxml_addattrib(ndxml *parent, const char *name, const char *value)
{
	struct ndxml_attr *attrib_node;
	if(!name || !value)
		return NULL ;
	attrib_node = alloc_attrib_node(name, value) ;
	if(attrib_node) {
		list_add_tail(&attrib_node->lst, &parent->lst_attr) ;
		(parent->attr_num)++ ;
	}
	return attrib_node ;

}


int ndxml_setattrval(ndxml *parent, const char *name, const char *value)
{
	int len = 0 ;
	struct ndxml_attr  * attr ;

	if( !name) {
		return -1 ;
	}
	if(!value || (len  = (int)ndstrlen(value)) == 0) {
		return ndxml_delattrib(parent, name) ;
	}

	attr =ndxml_getattrib(parent,  name);

	if(!attr) {
		struct ndxml_attr  * attr =ndxml_addattrib(parent,name, value)  ;
		if(attr) {
			return 0 ;
		}
		return -1 ;
	}
	
	++len ;
	if(len > attr->value_size) {
		struct ndxml_attr *attrib_node;
		attrib_node = alloc_attrib_node((char*)(attr + 1), value) ;
		if(!attrib_node) {
			return -1 ;
		}
		list_add(&attrib_node->lst, &attr->lst);

		list_del(&attr->lst) ;
		dealloc_attrib_node(attr);
	}
	else {
		ndstrncpy((char*)(attr + 1)+attr->name_size, value,attr->value_size) ;
	}
	return 0;
}
int ndxml_setattrvali(ndxml *parent, int index, const char *value)
{
	
	int len =0;
	struct ndxml_attr  * attr ;

	if( index <0 || index>= parent->attr_num) {
		return -1 ;
	}
	if(!value || (len  =(int) ndstrlen(value)) == 0) {
		return ndxml_delattribi(parent, index) ;
	}

	attr =ndxml_getattribi(parent,  index);

	if(!attr) {
		return -1 ;
	}
	
	++len;
	if(len > attr->value_size) {
		struct ndxml_attr *attrib_node;
		attrib_node = alloc_attrib_node((char*)(attr + 1), value) ;
		if(!attrib_node) {
			return -1 ;
		}
		list_add(&attrib_node->lst, &attr->lst);

		list_del(&attr->lst) ;
		dealloc_attrib_node(attr);
		return 0 ;
	}
	else {
		ndstrncpy((char*)(attr + 1)+attr->name_size, value,attr->value_size) ;
	}
	return 0;
}
//给xml增加一个子节点需要输入新节点的名字和值,返回新节点地址
ndxml *ndxml_addsubnode(ndxml *parent, const char *name, const char *value)
{
	ndxml *xmlnode = _create_xmlnode(name, value) ;
	if(xmlnode){
		list_add_tail(&xmlnode->lst_self, &parent->lst_sub);
		xmlnode->parent = parent;
		parent->sub_num++ ;
	}
	return xmlnode ;
}


int ndxml_setval_int(ndxml *node, int val)
{
	char buf[20];
	ndsnprintf(buf, sizeof(buf), "%d", val);
	return ndxml_setval(node, buf);
}

int ndxml_setval_float(ndxml *node, float val)
{
	char buf[20];
	ndsnprintf(buf,sizeof(buf), "%f", val);
	return ndxml_setval(node, buf);

}
//设置XML的值
int ndxml_setval(ndxml *node , const char *val)
{
	int len;
	if (!val || !*val) {
		if (node->value){
			node->value[0] = 0;
		}
		return 0;
	}

	len = (int) ndstrlen(val) +1 ;

	if (len > node->val_size ) {
		char *tmp = malloc(len);
		if (!tmp) {
			return -1;
		}
		if (node->value) {
			free(node->value);
		}
		node->val_size = len;
		node->value = tmp;
	}

	ndstrncpy(node->value, val, node->val_size);

	return 0 ;
}
//删除一个属性节点
int ndxml_delattrib(ndxml *parent, const char *name)
{
	struct ndxml_attr *attr= ndxml_getattrib(parent , name);
	if(!attr)
		return -1 ;
	list_del(&attr->lst) ;
	parent->attr_num-- ;
	dealloc_attrib_node(attr);
	return 0 ;

}
int ndxml_delattribi(ndxml *parent, int index) 
{
	struct ndxml_attr *attr= ndxml_getattribi(parent , index);
	if(!attr)
		return -1 ;
	list_del(&attr->lst) ;
	parent->attr_num-- ;
	dealloc_attrib_node(attr);
	return 0 ;
}
//删除一个子节点
int ndxml_delsubnode(ndxml *parent, const char *name)
{
	ndxml *node = ndxml_refsub(parent,name) ;
	if(!node)
		return -1 ;
	list_del(&node->lst_self) ;
	parent->sub_num-- ;
	dealloc_xml(node);
	return 0 ;
}

int ndxml_delsubnodei(ndxml *parent, int index) 
{
	ndxml *node = ndxml_refsubi(parent,index) ;
	if(!node)
		return -1 ;
	list_del(&node->lst_self) ;
	parent->sub_num-- ;
	dealloc_xml(node);
	return 0 ;
}

int ndxml_del_all_children(ndxml *parent)
{
	int ret = parent->sub_num;
	ndxml *sub_xml;
	struct list_head *pos, *next;
	list_for_each_safe(pos, next, &parent->lst_sub) {
		sub_xml = list_entry(pos, struct tagxml, lst_self);
		list_del(&sub_xml->lst_self);
		dealloc_xml(sub_xml);
	}
	parent->sub_num = 0 ;
	return ret;
}
//////////////////////////////////////////////////////////////////////////
//去掉注释
// static const char* parse_marked(const char *xmlbuf, int size, const char **error_addr) 
// {
// 	const char *pstart = xmlbuf ;
// 	const char *paddr;
// 	
// 	while(pstart< xmlbuf+size) {
// 		*error_addr = pstart ;
// 		//paddr = ndstrchr(pstart, '<') ;
// 		paddr =  ndstr_first_valid(pstart) ;
// 		if (!paddr || *paddr != '<') {
// 			//*error_addr = pstart ;
// 			return NULL ;
// 		}
// 
// 		if(!paddr || paddr >= xmlbuf+size) {
// 			*error_addr = 0 ;
// 			return NULL ;
// 		}
// 		if('?'==paddr[1]) {
// 			paddr = ndstrstr(paddr+2, "?>") ;
// 			if(!paddr || paddr >= xmlbuf+size) {
// 				return NULL ;
// 			}
// 			paddr += 2 ;
// 		}
// 		else if(paddr[1]=='!' ) {
// 			if(paddr[2]=='-' && paddr[3]=='-') {
// 				paddr = ndstrstr(paddr+4, "-->") ;
// 				if(!paddr || paddr >= xmlbuf+size) {
// 					return NULL ;
// 				}
// 				paddr += 3 ;
// 			}
// 			else {
// 				return NULL ;
// 			}
// 		}
// 		else {
// 			*error_addr = NULL ;
// 			return paddr ;
// 		}
// 		
// 		pstart = paddr ;
// 	}
// 	return NULL ;
// }

//new function block
int _parse_marked(ndxml *xml, const char *srcText)
{
	const char *p = srcText;

	if ('?' == *p) {
		p = ndstrstr(p + 1, "?>");
		if (!p || !*p) {
			return -1;
		}
		p += 2;
	}
	else if ('!' == *p) {
		if (p[1] == '-' && p[2] == '-') {
			p += 2;

			p = ndstrstr(p + 1, "-->");
			if (!p || !*p) {
				return -1;
			}
			p += 3;

		}
		else {
			return -1;
		}
	}


	return (int)(p - srcText);
}

int _parse_attr(ndxml *xml, const char *srcText)
{
	const char *p = srcText;
	do {
		struct ndxml_attr *attrib_node;
		char attr_name[MAX_XMLNAME_SIZE];
		//int ret;

		p = ndstr_first_valid(p);
		if (!p || !*p) {
			return -1;
		}
		else if (*p == '/' || *p == '>') {
			return (int)(p - srcText);
		}

		p = ndstr_parse_word_n(p, attr_name, sizeof(attr_name));
		if (!p) {
			return -1;
		}

		p = ndstrchr(p, '=');

		if (!p ) {
			return -1;
		}
		else {
			char buf[4096];
			buf[0] = 0;
			p = _xml_read_attrval(p, buf, sizeof(buf));
			if (!p) {
				return -1;
			}
			//------------------

			attrib_node = alloc_attrib_node(attr_name, buf);
			if (attrib_node) {
				list_add_tail(&attrib_node->lst, &xml->lst_attr);
				(xml->attr_num)++;
			}
		}
	} while (*p);

	return -1;
}

int _parse_value(ndxml *xml, const char *srcText)
{
	const char *p = srcText;
	size_t val_size;
	
	val_size = _xml_get_value_size(p);
	if (val_size == 0) {
		return -1;
	}
	++val_size;

	val_size += 4; val_size &= ~3;
	xml->value = malloc(val_size);
	nd_assert(xml->value);
	xml->value[0] = 0;
	xml->val_size = val_size;

	p = _xml_read_value(p, xml->value, val_size);
	
	return (int)(p - srcText);

}

//parse end 
int _parse_end(ndxml *xml, const char *srcText)
{
	const char *p = ndstr_first_valid(srcText);
	char end_name[MAX_XMLNAME_SIZE+4];

	p = ndstr_parse_word_n(p, end_name, MAX_XMLNAME_SIZE);
	if (!p) {
		return -1;
	}

	if (0!=ndstricmp(xml->name,end_name)){
		return -1;
	}

	p = strchr(p,'>');
	if (!p || !*p) {
		return -1;
	}
	++p;
	return (int)(p - srcText);
}

int _parse_new_xml(ndxml **xmlOut, const char *srcText, const char **pErrorAddr)
{
	ndxml *xml;
	int ret = 0;
	const char *p = ndstr_first_valid(srcText);

	*xmlOut = NULL;
	*pErrorAddr = srcText;
	if (!p || !*p) {
		return -1;
	}

	if (*p != '<') {
		return -1;
	}

	//skip mark-comment
	++p;
	if (*p == '!' || *p == '?' ) {
		ret = _parse_marked(NULL, p);
		if (ret > 0) {
			p += ret;
			*xmlOut = NULL;
			*pErrorAddr = srcText;
			return (int)(p - srcText);
		}
		else {
			return -1;
		}
	}
	//parse name 
	xml =  alloc_xml();
	nd_assert(xml);
	*xmlOut = xml;

	p = ndstr_parse_word_n(p, xml->name, MAX_XMLNAME_SIZE);
	if (!p) {
		dealloc_xml(xml);
		return -1;
	}

	*pErrorAddr = p;
	//parse attribtue 
	ret = _parse_attr(xml, p);
	
	if (-1 == ret) {
		dealloc_xml(xml);
		return -1;
	}
	p += ret;

	//check is end
	if (*p == '/') {
		//parse end 
		if (p[1] == '>') {
			p+= 2 ;
			return (int)(p - srcText);
		}
		else {
			dealloc_xml(xml);
			return -1;
		}
	}
	else if (*p != '>') {
		dealloc_xml(xml);
		return -1;
	}

	p = ndstr_first_valid(p+1);
	if (!p || !*p) {
		return -1;
	}

	if (*p == '<') {
		do {
			ndxml *subxml = NULL;
			if (p[1] == '/') {
				p+=2;
				break;
			}

			ret = _parse_new_xml(&subxml, p,pErrorAddr);
			if (-1 == ret) {
				dealloc_xml(xml);
				return -1;
			}
			if (subxml) {
				list_add_tail(&subxml->lst_self, &xml->lst_sub);
				subxml->parent = xml;
				xml->sub_num++;
			}
			p += ret;
			p = ndstr_first_valid(p);
		} while (*p == '<');
	}
	else {
		ret = _parse_value(xml, p);
		if (-1 == ret) {
			dealloc_xml(xml);
			return -1;
		}
		p += ret;
		p += 2;// skip </

	}

	*pErrorAddr = p;

	ret = _parse_end(xml, p);
	if (-1 == ret) {
		dealloc_xml(xml);
		return -1;
	}
	p += ret;
	return (int)(p - srcText);

}
//从内存块中解析出一个XML节点
ndxml *parse_xmlbuf(const char *xmlbuf, int size, const char **parse_end, const char **error_addr)
{
	ndxml *xmlnode = NULL;

	int ret = _parse_new_xml(&xmlnode, xmlbuf, error_addr);
	if (ret == -1) {
		if (*error_addr == NULL) {
			*error_addr = xmlbuf;
		}
		return NULL;
	}
	else {
		*parse_end = xmlbuf + ret;
		*error_addr = NULL;
		return xmlnode;
	}

}


//申请一个节点内存
ndxml *alloc_xml(void)
{
	ndxml *node = malloc(sizeof(ndxml)) ;
	if(node) {
		init_xml_node(node) ;
	}
	return node ;
}

void _release_xml(ndxml *node)
{
	struct list_head *pos ;	
	//dealloc value 
	if(node->value) {
		free(node->value) ;
		node->value = 0 ;
		node->val_size = 0;
	}

	//dealloc attribute
	pos = node->lst_attr.next ;
	while(pos != &node->lst_attr) {
		struct ndxml_attr *attrnode ;
		attrnode = list_entry(pos, struct ndxml_attr, lst) ;
		pos = pos->next ;
		dealloc_attrib_node(attrnode) ;
	}

	//dealloc sub-xmlnode 
	pos = node->lst_sub.next ;
	while(pos != &node->lst_sub) {
		struct tagxml  *_xml ;
		_xml = list_entry(pos, struct tagxml, lst_self) ;
		pos = pos->next ;
		list_del(&_xml->lst_self) ;
		dealloc_xml(_xml) ;
	}

}

//释放一个XML节点的所以资源
void  dealloc_xml(ndxml *node)
{
	_release_xml(node);
	free(node);
}


//申请一个属性节点的内存
struct ndxml_attr *alloc_attrib_node(const char *name, const char *value)
{
	char *p ;
	struct ndxml_attr *pnode ;
	int len = (int) ndstrlen(name) +1;
    int val_reallen = value ? (int) ndstrlen(value) : 0 ;
	int val_len = val_reallen + 1;
	
	len += 4 ;
	len &= ~3 ;
    
	pnode = malloc(sizeof(struct ndxml_attr) + len + val_len) ;
	
	if(!pnode) {
		return NULL ;
	}
	init_xml_attr(pnode) ;

	pnode->name_size = len ;
	pnode->value_size = val_len ;

	p = (char*) (pnode + 1) ;
	ndstrncpy(p , name,len) ;

	p += len ;
    if (val_reallen > 0) {
        ndstrncpy(p, value, val_len) ;
    }
    else {
        *p = 0;
    }

	return pnode ;
}

//释放一个属性节点内存资源
void dealloc_attrib_node(struct ndxml_attr *pnode)
{
	list_del(&pnode->lst);
	free(pnode) ;
}

//create a xml node input name and value 
ndxml *_create_xmlnode(const char *name, const char *value)
{
	ndxml *xmlnode ;
	
	if(!name)
		return NULL ;

	xmlnode = alloc_xml() ;
	if(!xmlnode) {
		return NULL ;
	}
	ndstrncpy(xmlnode->name,	name,MAX_XMLNAME_SIZE) ;
	if (-1 == ndxml_setval(xmlnode, value)) {
		free(xmlnode);
		return NULL;
	}
	return xmlnode;

}

static __INLINE__ void indent(FILE *fp, int deep)
{
	while(deep-- > 0) {
		_stream_to_file(fp,"\t");
	}
}

static size_t get_xml_value_size(ndxml *xmlnode)
{
	size_t ret = xmlnode->val_size;

	struct list_head *pos ;
	list_for_each(pos, &xmlnode->lst_attr) {
		struct ndxml_attr *xml_attr = list_entry(pos, struct ndxml_attr, lst);

		if (xml_attr->value_size > ret) {
			ret = xml_attr->value_size;
		}
	}
	return ret;
}

//把xml写到文件中
//@deep 节点的深度
#define XML_VALUE_SIZE 256
int xml_write(ndxml *xmlnode, FILE *fp , int deep)
{
	struct list_head *pos ;
	size_t value_buffer_size = get_xml_value_size(xmlnode);
	char *textBuf;

	if (value_buffer_size < XML_VALUE_SIZE) {
		value_buffer_size = 1024;
	}
	else {
		value_buffer_size += 4096;
	}

	textBuf = (char*)malloc(value_buffer_size);
	if (!textBuf) {
		return -1;
	}

	indent(fp,deep) ;
	_stream_to_file(fp, "<%s", xmlnode->name) ;
	
	//save attribute to file 
	pos = xmlnode->lst_attr.next ;
	while (pos != &xmlnode->lst_attr){
		struct ndxml_attr *xml_attr = list_entry(pos, struct ndxml_attr, lst) ;
        char *attr_val1 = (char*)(xml_attr + 1) +xml_attr->name_size ;
		pos = pos->next ;
        if( attr_val1[0] && xml_attr->value_size > 0) {
			textBuf[0] = 0;
			//attr_val1[xml_attr->value_size - 1] = 0;
			nd_assert(strlen(attr_val1) < (size_t)xml_attr->value_size);
			
			_stream_to_file(fp, " %s=\"%s\"", (char*)(xml_attr + 1), _out_replace_text(attr_val1, textBuf, value_buffer_size));
        }
        else {
			_stream_to_file(fp, " %s=\"\"", (char*)(xml_attr + 1)) ;
        }
	}
	
	//save value of sub-xmlnode
	if(xmlnode->value && xmlnode->value[0]) {
		textBuf[0] = 0;
		nd_assert(strlen(xmlnode->value) < (size_t)xmlnode->value);
		_stream_to_file(fp, ">%s</%s>\n", _out_replace_text(xmlnode->value, textBuf, value_buffer_size), xmlnode->name);
	}
	else if (xmlnode->sub_num>0){
		_stream_to_file(fp, ">\n") ;

		pos = xmlnode->lst_sub.next ;
		while (pos != &xmlnode->lst_sub){
			ndxml *subxml = list_entry(pos, struct tagxml, lst_self) ;
			pos = pos->next ;
			xml_write(subxml, fp , deep+1);
		}
		indent(fp,deep) ;
		_stream_to_file(fp, "</%s>\n", xmlnode->name) ;
	}
	else {
		_stream_to_file(fp, "/>\n") ;
	}
	free(textBuf);
	return 0 ;
}

int xml_tobuf(ndxml *xmlnode, char *buf, size_t size)
{
	int len;
	char *p = buf;
	struct list_head *pos;

	char textBuf[4096];
	
	//indent(fp, deep);
	len = ndsnprintf(p,size, "<%s", xmlnode->name);
	p += len; 
	size -= len;

	//save attribute to file 
	pos = xmlnode->lst_attr.next;
	while (pos != &xmlnode->lst_attr){
		struct ndxml_attr *xml_attr = list_entry(pos, struct ndxml_attr, lst);
		char *attr_val1 = (char*)(xml_attr + 1) + xml_attr->name_size;
		pos = pos->next;
		if (attr_val1[0]) {
			textBuf[0] = 0;
			len = ndsnprintf(p, size, " %s=\"%s\"", (char*)(xml_attr + 1), _out_replace_text(attr_val1, textBuf, sizeof(textBuf)));
			p += len;
			size -= len;

		}
		else {
			len = ndsnprintf(p, size, " %s=\"\"", (char*)(xml_attr + 1));
			p += len;
			size -= len;

		}
	}

	//save value of sub-xmlnode
	if (xmlnode->value && xmlnode->value[0]) {
		textBuf[0] = 0;
		len = ndsnprintf(p, size, ">%s</%s> ", _out_replace_text(xmlnode->value, textBuf, sizeof(textBuf)), xmlnode->name);
		p += len;
		size -= len;

	}
	else if (xmlnode->sub_num > 0){
		len = ndsnprintf(p, size, "> ");
		p += len;
		size -= len;


		pos = xmlnode->lst_sub.next;
		while (pos != &xmlnode->lst_sub){
			ndxml *subxml = list_entry(pos, struct tagxml, lst_self);
			pos = pos->next;
			len = xml_tobuf(subxml, p, size);
			p += len;
			size -= len;

		}
		//indent(fp, deep);
		len = ndsnprintf(p, size, "</%s> ", xmlnode->name);
		p += len;
		size -= len;

	}
	else {
		len = ndsnprintf(p, size, "/> ");
		p += len;
		size -= len;

	}
	return (int) (p-buf);
}

int _errlog (const char *errdesc)
{
	return ndfprintf(stderr,"%s", errdesc) ;
}

int ndxml_output(ndxml *node, FILE *pf)
{
	return xml_write(node, pf, 0);
}


size_t ndxml_to_buf(ndxml *rootNode, char *buf, size_t size)
{
	const char *name = ndxml_getname(rootNode);
	if (name && *name){
		//is common xml
		return xml_tobuf(rootNode, buf, size);
	}
	else {
		size_t ret = 0;
		struct list_head *pos = rootNode->lst_sub.next;
		char *p = buf;
		while (pos != &rootNode->lst_sub) {
			ndxml *sub_xml = list_entry(pos, struct tagxml, lst_self);
			pos = pos->next;
			size_t len = xml_tobuf(sub_xml, p, size);
			p += len;
			size -= len; 
			ret += len;
		}
		return ret;
	}
}
//////////////////////////////////////////////////////////////////////////
//function of recursive getter/setter 

static const char *_get_attrname_from_path(const char *attr_path_name)
{
	const char *start = attr_path_name;
	size_t size = ndstrlen(start);
	const char *p = start + size;

	int ret = 0;

	while (p-- > start){
		if (*p == '.'){
			ret = 1;
			break;
		}
		else if (*p == '/')	{
			ret = 0;
			break;
		}
	}

	if (ret){
		return p + 1;
	}
	return NULL;
}

ndxml* ndxml_recursive_ref(ndxml *node, const char *xmlNodePath)
{
	//const char *p = ndxml_getval(node);
	const char *p = xmlNodePath;
	char nodeName[MAX_XMLNAME_SIZE];

	ndxml *retXml = NULL;
	if (!p || !*p){
		return NULL;
	}
	
	if (*p == '/') {
		ndxml *root = NULL;
		do {
			root = ndxml_get_parent(node);
			if (root) {
				node = root;
			}
		} while (root);
		retXml = root;
	}
	else if (*p == '.' && *(p + 1) == '/') {
		++p; ++p;
		retXml = node;
	}

	while (p && *p && node)	{
		if (*p == '/') {
			++p;
		}

		nodeName[0] = 0;
		p = ndstr_nstr_ansi(p, nodeName, '/', 128);
		if (ndstrcmp(nodeName, "..") == 0){
			retXml = ndxml_get_parent(node);
		}
		else if (nodeName[0]) {
			//skip node.attrName
			char *attrNameStart = ndstrchr(nodeName, '.');
			if (attrNameStart)	{
				*attrNameStart = 0;
				if (!*nodeName)	{
					return node;
				}
				else {
					return ndxml_getnode(node, nodeName);
				}
			}
			else {
				retXml = ndxml_getnode(node, nodeName);
			}
		}
		else {
			break;
		}
		node = retXml;
	}

	return retXml;
}

const char* ndxml_recursive_getval(ndxml *node, const char *xmlNodePath)
{
	ndxml*xml = ndxml_recursive_ref(node, xmlNodePath);
	if (!xml){
		return NULL;
	}
	return ndxml_getval(xml);
}

int ndxml_recursive_setval(ndxml *node, const char *xmlNodePath, const char *val)
{
	ndxml*xml = ndxml_recursive_ref(node, xmlNodePath);
	if (!xml){
		return -1;
	}
	return ndxml_setval(xml, val);
}

// get xml node attribute value with recursive : ndxml_recursive_ref(xml, "../../node1/subnode.name")
const char* ndxml_recursive_getattr(ndxml *node, const char *xmlAttrPathName)
{
	const char *pAttrName = _get_attrname_from_path(xmlAttrPathName);
	if (!pAttrName)	{
		return NULL;
	}

	ndxml*xml = ndxml_recursive_ref(node, xmlAttrPathName);
	if (!xml){
		return NULL;
	}
	return ndxml_getattr_val(xml, pAttrName);
}

int ndxml_recursive_setattr(ndxml *node, const char *xmlAttrPathName, const char *attrVal)
{
	const char *pAttrName = _get_attrname_from_path(xmlAttrPathName);
	if (!pAttrName)	{
		return -1;
	}

	ndxml*xml = ndxml_recursive_ref(node, xmlAttrPathName);
	if (!xml){
		return -1;
	}
	return ndxml_setattrval(xml, pAttrName, attrVal);

}
