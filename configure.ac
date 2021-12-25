AC_INIT([namescan], [0.1.3], [lomato@gmail.com], [namescan], [http://github.com/crondaemon/namescan])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 no-define foreign])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CPP
AM_PROG_CC_C_O
AC_CONFIG_FILES([Makefile])
AC_CHECK_LIB([pcap],[pcap_open_live], [], AC_MSG_ERROR([unable to find the pcap_open_live() function]))
AC_CHECK_LIB([pthread],[pthread_create], [], AC_MSG_ERROR([unable to find the pthread_create() function]))
AC_OUTPUT
