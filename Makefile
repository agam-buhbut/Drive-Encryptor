.PHONY: build install uninstall clean help

INSTALL_DIR := $(HOME)/.local/bin
APP_DIR     := $(HOME)/.local/share/applications
DESKTOP_DIR := $(HOME)/Desktop
ICON_DIR    := $(HOME)/.local/share/icons/hicolor/256x256/apps
ICON_SRC    := $(CURDIR)/crates/gui/icons/icon.png
CLI_BIN     := drive-encryptor
GUI_BIN     := drive-encryptor-gui
APP_NAME    := DriveEncryptor

build:
	cargo build --release

install: build
	@mkdir -p $(INSTALL_DIR) $(APP_DIR) $(DESKTOP_DIR) $(ICON_DIR)
	cp target/release/$(CLI_BIN) $(INSTALL_DIR)/$(CLI_BIN)
	cp target/release/$(GUI_BIN) $(INSTALL_DIR)/$(GUI_BIN)
	cp $(ICON_SRC) $(ICON_DIR)/$(CLI_BIN).png
	@{ \
		echo '[Desktop Entry]'; \
		echo 'Version=1.0'; \
		echo 'Type=Application'; \
		echo 'Name=$(APP_NAME)'; \
		echo 'Comment=Encrypt and manage drives'; \
		echo 'Exec=$(GUI_BIN)'; \
		echo 'Icon=$(CLI_BIN)'; \
		echo 'Terminal=false'; \
		echo 'Categories=Utility;Security;'; \
		echo 'StartupNotify=true'; \
	} > $(APP_DIR)/$(APP_NAME).desktop
	cp $(APP_DIR)/$(APP_NAME).desktop $(DESKTOP_DIR)/$(APP_NAME).desktop
	@gio set $(DESKTOP_DIR)/$(APP_NAME).desktop metadata::trusted true 2>/dev/null || true
	@command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database $(APP_DIR) || true
	@command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t $(HOME)/.local/share/icons/hicolor 2>/dev/null || true
	@echo "Installed $(APP_NAME)"

uninstall:
	rm -f $(INSTALL_DIR)/$(CLI_BIN)
	rm -f $(INSTALL_DIR)/$(GUI_BIN)
	rm -f $(ICON_DIR)/$(CLI_BIN).png
	rm -f $(APP_DIR)/$(APP_NAME).desktop
	rm -f $(DESKTOP_DIR)/$(APP_NAME).desktop
	@command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database $(APP_DIR) || true
	@command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t $(HOME)/.local/share/icons/hicolor 2>/dev/null || true
	@echo "Uninstalled $(APP_NAME)"

clean:
	cargo clean

help:
	@echo "Targets:"
	@echo "  build      Build release binaries"
	@echo "  install    Build and install CLI + GUI desktop entry"
	@echo "  uninstall  Remove installed binaries and desktop entry"
	@echo "  clean      Remove build artifacts"
