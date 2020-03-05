# 包括两个 .mk 文件
ifeq ($(wildcard ../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../mk/platform.mk

ifeq ($(wildcard ../mk/PcapPlusPlus.mk),)
  $(error PcapPlusPlus.mk not found! Please run configure script first)
endif

include ../mk/PcapPlusPlus.mk

# 获取所有源文件
SOURCES := $(wildcard src/*.cpp)
# 将所有 sec/*.cpp 文件转化为 Obj/*.o 目标文件
OBJS_FILENAMES_DEBUG := $(patsubst src/%.cpp,Obj/%.o,$(SOURCES))
# 过滤掉 Obj/debug_new.o 目标文件
OBJS_FILENAMES := $(filter-out Obj/debug_new.o,$(OBJS_FILENAMES_DEBUG))

ifdef WIN32
DEPS := -DWPCAP -DHAVE_REMOTE
endif

# 定义 LINUX 环境
ifdef LINUX
DEPS := -DLINUX
endif

ifdef MAC_OS_X
DEPS := -DMAC_OS_X
endif

ifdef FREEBSD
DEPS := -DFREEBSD
endif

# 获得 HEAD 的 SHA1 值
GIT_CUR_COMMIT := $(shell git rev-parse --verify HEAD)
GIT_CUR_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
DEPS += -DGIT_COMMIT=\"$(GIT_CUR_COMMIT)\" -DGIT_BRANCH=\"$(GIT_CUR_BRANCH)\"

# 增加头文件目录
INCLUDES := -I"./src" \
			-I"./header"
			
ifdef WIN32
INCLUDES += -I$(MINGW_HOME)/include/ddk \
			-I$(WINPCAP_HOME)/Include
endif

ifdef LINUX
INCLUDES += -I/usr/include/netinet
endif

ifdef MAC_OS_X
INCLUDES += -I$(MACOS_SDK_HOME)/usr/include/malloc
endif

# 生成目标文件
Obj/%.o: src/%.cpp
	@echo 'Building file: $<'
	@$(CXX) $(DEPS) $(INCLUDES) $(PCAPPP_BUILD_FLAGS) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"

CUR_TARGET := $(notdir $(shell pwd))

.SILENT:

all: start Common++.lib Common++.debug

start:
	@echo '==> Building target: $(CUR_TARGET)'

# 创建目录
create-directories:
	@$(MKDIR) -p Obj
	@$(MKDIR) -p Lib
	@$(MKDIR) -p Lib/Debug
	@$(MKDIR) -p Lib/Release

# AR -r 创建库文件
Common++.lib: create-directories $(OBJS_FILENAMES)
	@$(AR) -r "Lib/Release/$(LIB_PREFIX)Common++$(LIB_EXT)" $(OBJS_FILENAMES)
	@echo 'Finished successfully building: $@'
	@echo ' '

Common++.debug: create-directories $(OBJS_FILENAMES_DEBUG)
	@$(AR) -r "Lib/Debug/$(LIB_PREFIX)Common++$(LIB_EXT)" $(OBJS_FILENAMES_DEBUG)
	@echo 'Finished successfully building: $@'
	@echo ' '

clean:
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./Lib/*
	@echo 'Clean finished: $(CUR_TARGET)'
