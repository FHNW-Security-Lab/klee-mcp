/* 64-byte libxml2 harness — deeper than the 32-byte baseline. */
#include <stddef.h>
typedef struct _xmlDoc xmlDoc;
typedef xmlDoc *xmlDocPtr;
extern void        xmlInitParser(void);
extern void        xmlCleanupParser(void);
extern xmlDocPtr   xmlReadMemory(const char *buffer, int size,
                                 const char *URL, const char *encoding,
                                 int options);
extern void        xmlFreeDoc(xmlDocPtr cur);

int fuzz_xml64(const char *buf, int len) {
    if (len < 0 || len > 64) return -1;
    xmlInitParser();
    xmlDocPtr doc = xmlReadMemory(buf, len, 0, 0, 0);
    if (doc) xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}
