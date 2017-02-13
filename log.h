#ifndef _LOG_H
#define _LOG_H 1

#define DEBUG_LOG(info)                                                 \
  printk("FILE = %s, LINE = %d, FUNC = %s, INFO : %s\n", __FILE__, __LINE__, __FUNCTION__, info)

#endif
