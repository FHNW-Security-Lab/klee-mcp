/* Minimal libxml2 harness: parse a 32-byte symbolic buffer as XML in
 * memory. Targets memory-safety / integer bugs reachable from
 * xmlReadMemory's top-level parser. Whole-library libxml2.bc (9.4 MB)
 * is linked at verify time via extra_bitcodes.
 */
#include <stddef.h>
typedef struct _xmlDoc xmlDoc;
typedef xmlDoc *xmlDocPtr;

extern void        xmlInitParser(void);
extern void        xmlCleanupParser(void);
extern xmlDocPtr   xmlReadMemory(const char *buffer, int size,
                                 const char *URL, const char *encoding,
                                 int options);
extern void        xmlFreeDoc(xmlDocPtr cur);

int fuzz_xml(const char *buf, int len) {
    if (len < 0 || len > 32) return -1;
    xmlInitParser();
    xmlDocPtr doc = xmlReadMemory(buf, len, 0, 0, 0);
    if (doc) xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}
