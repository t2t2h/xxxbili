TARGET := iphone:clang:latest:14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

# مكتبة مستقلة (dylib) بدون أي اعتماد على Substrate / ElleKit
LIBRARY_NAME = DomainSniffer

DomainSniffer_FILES = Tweak.xm
DomainSniffer_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
DomainSniffer_FRAMEWORKS = UIKit Foundation QuartzCore AVFoundation

include $(THEOS_MAKE_PATH)/library.mk
