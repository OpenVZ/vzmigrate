/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#ifndef __REMOTECMD__
#define __REMOTECMD__

#define CMD_ARGUMENTS	"arguments"
#define CMD_BINARY	"binary"
#define CMD_VERSION 	"version"
#define CMD_START_PARAMS	"startparams"
#define CMD_CHECK_IPS	"checkips"
#define CMD_CHECK_DEPS	"checkdeps"
#define CMD_CHECK_CACHES	"checkcaches"
#define CMD_INIT	"init"
#define CMD_FIRST	"first"
#define CMD_DUMP	"dump"
#define CMD_SECOND	"second"
#define CMD_SECOND_CHECKSUM	"second_checksum"
#define CMD_SECOND_TRACKER	"second_tracker"
#define CMD_SECOND_BINDMOUNTS	"secondbindmounts"
#define CMD_SCRIPT	"script"
#define CMD_FINAL	"final"
#define CMD_RESUME	"resume"
#define CMD_DUMPCOPY	"dumpcopy"
#define CMD_SUSPENDCOPY	"suspendcopy"
#define CMD_PLOOP_COPY	"ploopcopy"
#define CMD_COPY_EXTERNAL_DISK "copyexternaldisk"
#define CMD_PLOOP_COPY_SYNC	"loopcopysync"
#define CMD_ONLINE_PLOOP_COPY_1	"onlineploopcopy1"
#define CMD_ONLINE_PLOOP_COPY_2	"onlineploopcopy2"
#define CMD_CREATE_PLOOP_SNAPSHOT	"createploopsnapshot"
#define CMD_CREATE_PLOOP_SNAPSHOT_NO_ROLLBACK	"createploopsnapshotNoRollback"
#define CMD_MERGE_PLOOP_SNAPSHOT	"mergeploopsnapshot"
#define CMD_NON_FINAL_RESUME		"nonfinalresume"
#define CMD_STOP		"stop"
#define CMD_MOUNT_PLOOP		"mountploop"
#define CMD_COPY_PLOOP_ROOT	"copyplooproot"
#define CMD_COPY_PLOOP_BINDMOUNTS	"copyploopbindmounts"
#define CMD_COPY_VZPACKAGES	"copyvzpackages"
#define CMD_NATIVE_QUOTA_SET	"nativequotaset"

#define CMD_UUID		"uuid"
#define CMD_VENAME		"vename"
#define CMD_UNDUMP		"undump"
#define CMD_CHECKLICENSE	"checklicense"
#define CMD_CHECKRATE		"checkrate"
#define CMD_CONFSET		"confset"
#define CMD_SCRIPTSET		"scriptset"
#define CMD_PING		"ping"
#define CMD_CAPS		"caps" /* unused */
#define CMD_CPT_VER		"cpt_ver" /* unused */
#define CMD_SLMONLY		"slmonly"
#define CMD_SWAPCH		"swapch"
#define CMD_ITERCH		"iterch"
#define CMD_INVERTLAZY		"invertlazy"

#define CMD_FIRSTEMPL		"firstempl"
#define CMD_FINTEMPL		"fintempl"
#define CMD_SYNCTT		"synctt"


#define CMD_CHECK_NEWTEM_DEPS		"check_newtem_deps"
#define CMD_REPAIR_NEWTEM_PACKAGES	"repair_newtem_packages"

#define CMD_COPY_EZDIR_TAR		"syncezdir"

#define CMD_CHECK_TECHNOLOGIES		"checktechnologies"
#define CMD_CHECK_CLUSTER		"checkcluster"
#define CMD_CHECK_CLUSTER_DUMP		"checkclusterdump"
#define CMD_CHECK_SHARED_PRIV		"checksharedpriv"
#define CMD_CHECK_SHARED_FILE		"checksharedfile"
#define CMD_CHECK_SHARED_DUMP		"checkshareddump"
#define CMD_CHECK_CLUSTER_TMPL		"checkclustertmpl"
#define CMD_CHECK_SHARED_TMPL		"checksharedtmpl"
#define CMD_CLUSTER_DUMPCOPY		"clusterdumpcopy"
#define CMD_CHECK_EZDIR			"checkezdir"
#define CMD_CHECK_KEEP_DIR		"checkkeepdir"
#define CMD_CHECK_DISKSPACE		"checkdiskspace"
#define CMD_CHECK_OPTIONS		"checkoptions"
#define CMD_ADJUST_TMO			"adjusttmo"
#define CMD_COPY_EZCACHE		"copyezcache"
#define CMD_CHECK_KERNEL_MODULES	"checkkernelmodules"
#define CMD_HA_CLUSTER_NODE_ID		"haclusternodeid"
#define CMD_CHECK_PLOOP_FORMAT		"checkploopformat"
#endif

