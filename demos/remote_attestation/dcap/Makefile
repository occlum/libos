BIN_PATH := bin
OBJ_PATH := obj
SRC_PATH := src
INC_PATH := include
SGX_SDK_INC_PATH := /opt/intel/sgxsdk/include

CC := gcc
CCFLAGS := -I$(INC_PATH) -I$(SGX_SDK_INC_PATH)
CCOBJFLAGS := $(CCFLAGS) -c

TARGET_NAME := dcap_demo
TARGET := $(BIN_PATH)/$(TARGET_NAME)

SRC := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))

CLEAN_LIST := $(BIN_PATH)  $(OBJ_PATH)

.PHONY: all mkdir clean

default: mkdir all

mkdir:
	@mkdir -p $(BIN_PATH) $(OBJ_PATH)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CCFLAGS) -o $@ $(OBJ)

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c*
	$(CC) $(CCOBJFLAGS) -o $@ $<

clean:
	@rm -rf $(CLEAN_LIST)
