bin_dir = ./bin
obj_dir = ./obj
src_dir = ./src
include_dir = ./include

ifeq ($(OS),Windows_NT)
    lib_ext = dll
else
    lib_ext = so
endif
lib_name = libsoerudp.$(lib_ext)

srcs = $(wildcard $(src_dir)/*.c)
objs = $(subst $(src_dir),$(obj_dir),$(srcs:.c=.o))

all: $(bin_dir)/$(lib_name)

CFLAGS = -I$(include_dir) -fPIC -lzlib
$(bin_dir)/$(lib_name): $(objs)
	cc -shared -o $@ $(CFLAGS) $(objs)

%.c: $(include_dir)/%.h

$(obj_dir)/%.o: $(src_dir)/%.c
	cc -c -o $(obj_dir)/$(@F) $< $(CFLAGS)

.PHONY: clean
clean:
	$(RM) $(wildcard $(bin_dir)/*.$(lib_ext))
	$(RM) $(wildcard $(obj_dir)/*.o)
