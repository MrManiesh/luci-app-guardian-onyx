include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI Security Suite - Guardian Onyx (AdGuard Home, Firewall & Threat Management)
LUCI_DEPENDS:=+luci-base +curl +ca-bundle +jq
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-guardian-onyx
PKG_VERSION:=1.2
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Manish Choudhary

ifneq ($(wildcard $(TOPDIR)/feeds/luci/luci.mk),)
  include $(TOPDIR)/feeds/luci/luci.mk
else
  include $(INCLUDE_DIR)/package.mk

  define Package/$(PKG_NAME)
    SECTION:=luci
    CATEGORY:=LuCI
    SUBMENU:=3. Applications
    TITLE:=$(LUCI_TITLE)
    DEPENDS:=$(LUCI_DEPENDS)
    PKGARCH:=$(LUCI_PKGARCH)
  endef

  define Package/$(PKG_NAME)/description
    Guardian Onyx - A modern, responsive security management dashboard for OpenWrt.
    Manage AdGuard Home DNS filtering, view and control firewall zones and rules,
    monitor connected clients for threats, and track banned IPs.
  endef

  define Package/$(PKG_NAME)/conffiles
/etc/config/guardian
  endef

  define Build/Configure
  endef

  define Build/Compile
  endef

  define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/
	cp -pR ./root/* $(1)/
	$(INSTALL_DIR) $(1)/www
	cp -pR ./htdocs/* $(1)/www/
	chmod 0755 $(1)/usr/libexec/* 2>/dev/null || true
	chmod 0755 $(1)/etc/init.d/* 2>/dev/null || true
  endef
endif

define Package/$(PKG_NAME)/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	chmod 0755 /etc/init.d/guardian 2>/dev/null || true
	chmod 0755 /usr/libexec/guardian* 2>/dev/null || true
	rm -rf /tmp/luci-indexcache /tmp/luci-modulecache /tmp/luci-sessions/*
	/etc/init.d/rpcd reload 2>/dev/null
	if [ -f /etc/init.d/guardian ]; then
		/etc/init.d/guardian enable 2>/dev/null
		/etc/init.d/guardian start 2>/dev/null
	fi
}
exit 0
endef

define Package/$(PKG_NAME)/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	if [ -f /etc/init.d/guardian ]; then
		/etc/init.d/guardian stop 2>/dev/null
		/etc/init.d/guardian disable 2>/dev/null
	fi
}
exit 0
endef

ifeq ($(wildcard $(TOPDIR)/feeds/luci/luci.mk),)
  $(eval $(call BuildPackage,$(PKG_NAME)))
endif
