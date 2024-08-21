TARGET := tcp
SRC_DIR := ./src
INC_DIRS := ./include
LIB_DIRS := ./lib
BUILD_DIR := ./bin

SRCS := $(shell find $(SRC_DIRS) -name '*.cpp' -or -name '*.c' -or -name '*.s')
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
LIBS := -lm

INC_FLAGS := $(addprefix -I,$(INC_DIRS))
CFLAGS := $(INC_FLAGS) -Wall

CC = gcc

$(BUILD_DIR)/$(TARGET): $(OBJS) 
	$(CC) $(OBJS) -o $@ $(LDFLAGS)


$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c 
	-mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean: 
	rm -rf $(BUILD_DIR)
