import AppKit
import SwiftUI

@main
@MainActor
final class ChatGPTMCPApp: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let control = ControlStore()
    private var window: NSWindow?
    private var statusItem: NSStatusItem?
    private var timer: Task<Void,Never>?
    private let background = CommandLine.arguments.contains("--background-login")

    static func main() {
        let app = NSApplication.shared
        let delegate = ChatGPTMCPApp()
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if background, let identifier = Bundle.main.bundleIdentifier,
           NSRunningApplication.runningApplications(withBundleIdentifier: identifier).contains(where: {
               $0.processIdentifier != ProcessInfo.processInfo.processIdentifier && !$0.isTerminated
           }) { NSApp.terminate(nil); return }

        let mainMenu = NSMenu()
        let appItem = NSMenuItem()
        mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appItem.submenu = appMenu
        add("Settings…", #selector(settings), ",", to: appMenu)
        appMenu.addItem(.separator())
        add("Quit ChatGPT MCP", #selector(quit), "q", to: appMenu)
        let editItem = NSMenuItem(title:"Edit",action:nil,keyEquivalent:"")
        mainMenu.addItem(editItem)
        let edit = NSMenu(title:"Edit")
        for (title,action,key) in [("Cut","cut:","x"),("Copy","copy:","c"),("Paste","paste:","v"),("Select All","selectAll:","a")] {
            edit.addItem(withTitle:title,action:Selector(action),keyEquivalent:key)
        }
        editItem.submenu=edit
        let viewItem = NSMenuItem(title:"View",action:nil,keyEquivalent:"")
        mainMenu.addItem(viewItem)
        let view = NSMenu(title:"View")
        add("Overview",#selector(show),"1",to:view)
        add("Settings",#selector(settings),"2",to:view)
        add("Activity & Logs",#selector(logs),"3",to:view)
        add("Maintenance & Recovery",#selector(maintenance),"4",to:view)
        add("Refresh",#selector(refresh),"r",to:view)
        viewItem.submenu=view
        NSApp.mainMenu = mainMenu

        let status = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        status.button?.image = NSImage(systemSymbolName:"point.3.connected.trianglepath.dotted",accessibilityDescription:"ChatGPT MCP")
        status.button?.toolTip = "ChatGPT MCP"
        let menu = NSMenu()
        add("Open ChatGPT MCP",#selector(show),"",to:menu)
        add("Settings…",#selector(settings),"",to:menu)
        add("Maintenance & Recovery",#selector(maintenance),"",to:menu)
        menu.addItem(.separator())
        add("Quit ChatGPT MCP",#selector(quit),"",to:menu)
        status.menu=menu
        statusItem=status
        control.applyAppearance()
        if background {
            NSApp.setActivationPolicy(.accessory)
            Task { await control.loginStartup() }
        } else { show() }
        timer = Task { [weak self] in
            while let self, !Task.isCancelled {
                let interval=UserDefaults.standard.object(forKey:"refreshSeconds") as? Int ?? 15
                try? await Task.sleep(for:.seconds(max(5,interval)))
                if !Task.isCancelled && interval>0 && self.window?.isVisible==true { await self.control.refresh() }
            }
        }
    }
    func add(_ title:String,_ selector:Selector,_ key:String,to menu:NSMenu) {
        let item = menu.addItem(withTitle:title, action:selector, keyEquivalent:key)
        item.target=self
    }
    func reveal(_ tab:Int?) {
        if let tab { control.tab=tab }
        if window==nil {
            let win=NSWindow(contentRect:NSRect(x:0,y:0,width:744,height:668),styleMask:[.titled,.closable,.miniaturizable,.resizable],backing:.buffered,defer:false)
            win.title="ChatGPT MCP";win.isReleasedWhenClosed=false;win.delegate=self
            win.contentViewController=NSHostingController(rootView:ControlWindow(control:control))
            win.minSize=NSSize(width:625,height:490)
            win.setContentSize(NSSize(width:744,height:668))
            win.center()
            win.setFrameAutosaveName("ChatGPTMCPControl")
            window=win
        }
        NSApp.setActivationPolicy(.regular)
        if window?.isMiniaturized==true {window?.deminiaturize(nil)}
        NSApp.unhide(nil);window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps:true)
        Task { await control.refresh() }
    }
    @objc func show(){reveal(0)}
    @objc func settings(){reveal(1)}
    @objc func logs(){reveal(2)}
    @objc func maintenance(){reveal(3)}
    @objc func refresh(){Task { await control.refresh() }}
    @objc func quit(){NSApp.terminate(nil)}
    func windowWillClose(_ notification: Notification){NSApp.setActivationPolicy(.accessory)}
    func applicationShouldHandleReopen(_ sender:NSApplication,hasVisibleWindows:Bool)->Bool {reveal(nil);return false}
    func applicationShouldTerminateAfterLastWindowClosed(_ sender:NSApplication)->Bool {false}
}
