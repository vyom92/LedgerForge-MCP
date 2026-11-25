import SwiftUI
import AppKit

struct SettingsPanel:View {
    @ObservedObject var control:ControlStore
    @AppStorage("appearance") var appearance="System"
    @AppStorage("refreshSeconds") var refreshSeconds=15
    @AppStorage("logLines") var logLines=40
    @AppStorage("logService") var logService="executor"
    @State private var login=LoginItem.enabled
    @State private var working=false
    @State private var localError:String?
    @State private var loadingPorts=false
    @State private var ports:PortConfig?
    @State private var values=[String:String]()
    var body:some View {
        ScrollView{
            VStack(alignment:.leading,spacing:17){
                VStack(alignment:.leading,spacing:9){
                    Text("General").font(.headline)
                    Toggle("Start in the background at Mac login",isOn:Binding(get:{login},set:{updateLogin($0)})).disabled(working)
                    Text("Open the window from the menu bar or Finder whenever you need it.").font(.caption).foregroundStyle(.secondary)
                    HStack{Picker("Appearance",selection:$appearance){ForEach(["System","Light","Dark"],id:\.self){Text($0)}}.fixedSize().onChange(of:appearance){_,_ in control.applyAppearance()}
                        Spacer()
                        Picker("Refresh status",selection:$refreshSeconds){Text("Manually").tag(0);ForEach([5,15,30,60],id:\.self){Text("Every \($0)s").tag($0)}}.fixedSize()}
                }
                Divider()
                VStack(alignment:.leading,spacing:8){
                    Text("Connections").font(.headline)
                    ForEach(control.state?.components ?? []){r in
                        HStack{Image(systemName:r.symbol).frame(width:22).foregroundStyle(.secondary)
                            VStack(alignment:.leading,spacing:2){Text(r.title);Text(r.name=="executor" ? "Backend listener":r.name=="admin-tunnel" ? "ledgerforge-recovery-admin":"ledgerforge-recovery").font(.caption).foregroundStyle(.secondary)}
                            Spacer();Text("Local port").foregroundStyle(.secondary)
                            TextField("Port",text:Binding(get:{values[r.name] ?? String(r.port)},set:{values[r.name]=$0}))
                                .textFieldStyle(.roundedBorder).frame(width:82).accessibilityLabel(r.title+" port").disabled(ports==nil || loadingPorts || control.phase != nil)
                        }
                    }
                    if let ports {
                        if ports.pending {Button("Restore previous ports…"){control.ask("Restore previous ports","An interrupted port change has a local recovery record. This restores its exact previous configuration and service state.",["restore-ports"])}}
                        else {HStack{
                            Text("Changes restart the affected listeners after an ownership check.").font(.caption).foregroundStyle(.secondary);Spacer()
                            Button("Apply ports…"){apply(ports)}.disabled(!changed || !valid || loadingPorts || control.phase != nil)
                        }}
                        if changed && !valid {Text("Choose three different ports between 1024 and 65535.").font(.caption).foregroundStyle(.orange)}
                    }
                }
                Divider()
                VStack(alignment:.leading,spacing:8){Text("Activity & Logs").font(.headline)
                    HStack{Picker("Default service",selection:$logService){ForEach(control.state?.components ?? []){Text($0.title).tag($0.name)}}.fixedSize();Spacer()
                        Picker("Recent lines",selection:$logLines){ForEach([15,40,70],id:\.self){Text(String($0)).tag($0)}}.fixedSize()}
                }
                Divider()
                CapabilitySettings(control:control)
                WideDisclosure(title:"Workspace and installation"){
                    location("Workspace",control.state?.workspace ?? ControlClient.root.deletingLastPathComponent().path)
                    location("Installation",ControlClient.root.path)
                    location("Python environment",ControlClient.root.appendingPathComponent(".venv").path)
                    let cfg=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/tunnel-client")
                    location("MCP Executor profile",cfg.appendingPathComponent("ledgerforge-recovery.yaml").path)
                    location("MCP Admin profile",cfg.appendingPathComponent("ledgerforge-recovery-admin.yaml").path)
                    location("Local recovery and deployment records",ControlClient.root.appendingPathComponent(".mcp-maintenance").path)
                    Button("Browse projects"){control.explore(.projects)}
                }
                WideDisclosure(title:"Maintenance actions"){
                    ForEach(SectionKind.allCases){kind in Button("Open "+kind.rawValue){control.explore(kind)}}
                    Button("Test local owner recovery"){Task{await control.perform(["self-test"],"Test owner recovery")}}
                }
                if let localError {Text(localError).foregroundStyle(.orange).textSelection(.enabled)}
            }.padding(.horizontal,22).padding(.vertical,8).frame(maxWidth:.infinity,alignment:.leading)
        }.task{await reload()}.onChange(of:control.revision){_,_ in Task{await reload()}}
    }
    func location(_ name:String,_ path:String)->some View {
        HStack{VStack(alignment:.leading){Text(name).font(.caption.bold());Text(path).font(.caption.monospaced()).textSelection(.enabled)};Spacer()
            Button("Show in Finder"){NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath:path)])}}
    }
    var integers:[String:Int]{values.compactMapValues(Int.init)}
    var changed:Bool {guard let ports else{return false};return values != ports.ports.mapValues{String($0)}}
    var valid:Bool {integers.count==3 && Set(integers.values).count==3 && integers.values.allSatisfy{(1024...65535).contains($0)}}
    func reload() async {
        login=LoginItem.enabled;loadingPorts=true
        let previous=ports?.ports.mapValues{String($0)}
        let draft=values
        defer{loadingPorts=false}
        do{
            let config=try await ControlClient.get(PortConfig.self,["ports"])
            let current=config.ports.mapValues{String($0)}
            if values==draft && (previous==nil || draft==previous || draft==current){values=current}
            ports=config;localError=nil
        }
        catch{localError=error.localizedDescription;ports=nil}
    }
    func apply(_ config:PortConfig){
        guard valid,let data=try? JSONEncoder().encode(integers) else{return}
        let body=String(decoding:data,as:UTF8.self)
        let affected=(control.state?.components ?? []).filter{config.ports["executor"] != integers["executor"] || config.ports[$0.name] != integers[$0.name]}
        let details=affected.map{$0.title+" · "+String(config.ports[$0.name] ?? 0)+" → "+String(integers[$0.name] ?? 0)}.joined(separator:"\n")
        control.ask("Apply port changes",details+"\n\nRunning services listed here will restart. A failed verification restores the previous configuration.",["configure-ports",body,"--confirm",config.identity])
    }
    func updateLogin(_ value:Bool){
        working=true
        Task{do {try await Task.detached{try LoginItem.set(value)}.value;login=LoginItem.enabled;localError=nil}
            catch {localError=error.localizedDescription;login=LoginItem.enabled};working=false}
    }
}
