import SwiftUI
import AppKit

struct WideDisclosure<Content:View>: View {
    let title:String
    @State var expanded:Bool=false
    @ViewBuilder let content:()->Content
    var body:some View {
        VStack(alignment:.leading,spacing:5) {
            Button {expanded.toggle()} label:{
                HStack(spacing:7){Image(systemName:expanded ? "chevron.down":"chevron.right").font(.caption.weight(.semibold)).frame(width:12);Text(title);Spacer(minLength:4)}
                    .padding(.horizontal,4).padding(.vertical,6).contentShape(Rectangle())
            }.buttonStyle(.plain).accessibilityLabel(title).accessibilityValue(expanded ? "Expanded":"Collapsed")
            if expanded{content().frame(maxWidth:.infinity,alignment:.leading).padding(.leading,19)}
        }
    }
}
struct ControlWindow:View {
    @ObservedObject var control:ControlStore
    var body:some View {
        VStack(alignment:.leading,spacing:0) {
            header.padding(.horizontal,22).padding(.vertical,15)
            Divider()
            HStack {
                Picker("Section",selection:$control.tab){
                    Text("Overview").tag(0);Text("Settings").tag(1);Text("Activity & Logs").tag(2);Text("Maintenance & Recovery").tag(3)
                }.pickerStyle(.segmented).labelsHidden().fixedSize()
                Spacer()
                Button {Task{await control.refresh();control.revision+=1}} label:{Image(systemName:"arrow.clockwise").padding(3)}
                    .help("Refresh current view").accessibilityLabel("Refresh current view").disabled(control.busy || control.refreshInFlight)
            }.padding(.horizontal,22).padding(.vertical,10)
            if let error=control.error {
                Label(error,systemImage:"exclamationmark.circle.fill").foregroundStyle(.red).font(.callout).textSelection(.enabled)
                    .frame(maxWidth:.infinity,alignment:.leading).padding(.horizontal,22).padding(.vertical,6)
            }
            if control.tab==3 {MaintenanceView(control:control)}
            else if control.tab==1 {SettingsPanel(control:control)}
            else if let s=control.state {
                if control.tab==0 {OverviewPanel(state:s,control:control)} else {LogPanel(state:s,control:control)}
            } else {
                VStack{Spacer();if control.error==nil{ProgressView("Reading local installation…")};Spacer()}.frame(maxWidth:.infinity)
            }
            if let line=control.phase ?? control.notice {
                Divider()
                HStack {if control.phase != nil{ProgressView().controlSize(.small)};Text(line).font(.callout).textSelection(.enabled);Spacer()}
                    .padding(.horizontal,22).padding(.vertical,8)
            }
        }
        .sheet(item:$control.confirmation){action in ConfirmAction(action:action,control:control)}
        .sheet(isPresented:Binding(get:{control.diagnostics != nil},set:{if !$0 {control.diagnostics=nil}})){
            VStack(alignment:.leading,spacing:12){
                Text("Connection diagnostics").font(.title2.bold())
                ScrollView{Text(control.diagnostics ?? "").font(.system(.callout,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)}
                HStack{Button("Copy"){copyText(control.diagnostics ?? "")};Spacer();Button("Done"){control.diagnostics=nil}.keyboardShortcut(.defaultAction)}
            }.padding(20).frame(minWidth:520,minHeight:370)
        }
    }
    var installedVersion:String {
        let file=ControlClient.root.appendingPathComponent(".mcp-release-version")
        if let version=try? String(contentsOf:file,encoding:.utf8).trimmingCharacters(in:.whitespacesAndNewlines),!version.isEmpty{return "Installed "+version}
        return "Local development services"
    }
    @ViewBuilder var header:some View {
        let s=control.state
        let error=(s.map{!$0.issues.isEmpty || $0.components.contains(where:{$0.state=="Ownership conflict"}) || ($0.components.first?.healthy==false && !$0.allOff)} ?? (control.error != nil))
        let good=s?.statusTitle=="Fully operational"
        HStack(spacing:12){
            if s==nil && control.error==nil {ProgressView().frame(width:43)}
            else {Image(systemName:good ? "checkmark.circle.fill":error ? "xmark.circle.fill":"exclamationmark.triangle.fill")
                .font(.system(size:38,weight:.semibold)).foregroundStyle(good ? Color.green:error ? Color.red:Color.yellow).accessibilityHidden(true)}
            VStack(alignment:.leading,spacing:3){
                Text(s?.statusTitle ?? (control.error==nil ? "Checking services…":"Status unavailable")).font(.title2.weight(.semibold))
                Text(s?.version.map{"Executor "+$0} ?? installedVersion).foregroundStyle(.secondary)
            }
            Spacer()
            if let s {
                if s.allOff {
                    Button("Start"){Task{await control.perform(["start"]+serviceCondition(s.service_identity),"Start services")}}.buttonStyle(.borderedProminent).disabled(!s.issues.isEmpty)
                } else if s.allReady || !s.issues.isEmpty {
                    Button("Stop"){askServices("stop",s:s,control:control)}.disabled(s.busyWork).help(s.busyWork ? "Active execution or recovery must finish first.":"Stop all three services")
                    Button("Restart"){askServices("restart",s:s,control:control)}.buttonStyle(.borderedProminent).disabled(s.busyWork).help(s.busyWork ? "Active execution or recovery must finish first.":"Restart all three services")
                } else if let item=s.components.first(where:{!$0.healthy}) {
                    Button("Repair "+item.title){repair(item,control:control)}.buttonStyle(.borderedProminent).disabled(item.state=="Ownership conflict")
                }
            }
        }.controlSize(.large).disabled(control.busy)
    }
}
func copyText(_ value:String){NSPasteboard.general.clearContents();NSPasteboard.general.setString(value,forType:.string)}
func serviceCondition(_ identity:String?)->[String]{identity.map{["--expected-services",$0]} ?? []}
func repair(_ service:Service,control:ControlStore){
    Task{await control.perform([service.name=="executor" ? "repair":"repair-connection",service.name]+serviceCondition(service.identity),"Repair "+service.title)}
}
@MainActor func askServices(_ op:String,s:Snapshot,control:ControlStore){
    let title=op=="stop" ? "Stop services":"Restart services"
    control.ask(title,"This interrupts both MCP connections and the Shared Tunnel. The controller checks all projects for active work before proceeding.",[op]+serviceCondition(s.service_identity))
}
struct OverviewPanel:View {
    let state:Snapshot
    @ObservedObject var control:ControlStore
    var body:some View{
        ScrollView {
            VStack(alignment:.leading,spacing:16){
                if let issue=state.issues.first {
                    VStack(alignment:.leading,spacing:6){Text(issue).font(.headline)
                        Text(guidance(issue)).foregroundStyle(.secondary).textSelection(.enabled)
                        Button("Review installation"){control.tab=1}
                    }
                } else if let project=state.recovery.first(where:{$0.value.stale==true}) {
                    VStack(alignment:.leading,spacing:5){Text("Lease recovery is available for "+project.key).font(.headline)
                        Button("Review lease"){control.explore(.leases,project.value.lease)}}
                } else if !state.allReady && !state.allOff,let missing=state.components.first(where:{!$0.healthy}) {
                    Text(missing.title+" is "+missing.state.lowercased()+". "+(missing.state=="Ownership conflict" ? "Inspect its listener ownership in diagnostics.":"Repair this component to restore service.")).foregroundStyle(.secondary)
                } else {Text(state.allOff ? "Start services when you need an MCP connection.":"All three services are ready. No intervention needed.").foregroundStyle(.secondary)}
                VStack(spacing:0){ForEach(state.components){row in
                    HStack(spacing:11){
                        Image(systemName:row.symbol).font(.title3).frame(width:25).foregroundStyle(.secondary)
                        VStack(alignment:.leading,spacing:2){Text(row.title).font(.headline);Text("Port "+String(row.port)+(row.pid.map{"  ·  PID "+String($0)} ?? "")).font(.caption.monospacedDigit()).foregroundStyle(.secondary)}
                        Spacer();Label(row.state,systemImage:row.healthy ? "checkmark.circle.fill":"minus.circle").foregroundStyle(row.healthy ? Color.green:Color.secondary)
                    }.padding(.vertical,8)
                    if row.id != state.components.last?.id {Divider()}
                }}
                Divider()
                VStack(alignment:.leading,spacing:5){Text("Workspace").font(.headline);Text(state.workspace).font(.system(.callout,design:.monospaced)).textSelection(.enabled)
                    WideDisclosure(title:state.projects.isEmpty ? "Browse local projects":"\(state.projects.count) project contexts"){
                        ForEach(state.projects){p in Button {control.explore(.projects,p.project)} label:{HStack{Text(p.project);Spacer();Text(p.available ? p.kind:"Unavailable").foregroundStyle(.secondary);Image(systemName:"chevron.right").font(.caption)}.padding(.vertical,4).contentShape(Rectangle())}.buttonStyle(.plain)}
                        if state.projects.isEmpty{Button("Discover projects on this Mac"){control.explore(.projects)}}
                    }}
                if let last=state.activity.last{Divider();VStack(alignment:.leading,spacing:4){Text("Recent activity").font(.headline);Text(last).font(.callout.monospacedDigit()).textSelection(.enabled)}}
            }.padding(.horizontal,22).padding(.vertical,9).frame(maxWidth:.infinity,alignment:.leading)
        }
    }
    func guidance(_ issue:String)->String{
        if issue.contains("Python"){return "Restore the installed Python environment from the configured interpreter and MCP dependencies. Settings shows its location."}
        if issue.contains("source") || issue.contains("component"){return "Inspect the named file and the verified release or rollback copy in Maintenance & Recovery."}
        if issue.contains("Workspace"){return "Make the configured workspace available at its recorded path."}
        if issue.contains("Port"){return "Inspect the port mapping and any interrupted change in Settings."}
        return "Open Settings for the installed paths and Maintenance & Recovery for related evidence."
    }
}
struct LogPanel:View {
    let state:Snapshot
    @ObservedObject var control:ControlStore
    @AppStorage("logService") private var service="executor"
    @AppStorage("logLines") private var lines=40
    @State private var filter=""
    var emptyDescription:String {
        if let path=state.log_paths?[service],!FileManager.default.isReadableFile(atPath:path){return "This service log is missing or unreadable at "+path}
        return filter.isEmpty ? "The service log has no recent lines.":"No lines match the current filter."
    }
    var body:some View{
        let text=(state.logs[service] ?? []).suffix(lines).filter{filter.isEmpty || $0.localizedCaseInsensitiveContains(filter)}.joined(separator:"\n")
        VStack(alignment:.leading,spacing:10){
            WideDisclosure(title:"Recent control activity"){Text(state.activity.joined(separator:"\n")).font(.caption.monospaced()).textSelection(.enabled)}
            HStack{Picker("Service log",selection:$service){ForEach(state.components){Text($0.title).tag($0.name)}}.fixedSize()
                TextField("Filter lines",text:$filter).textFieldStyle(.roundedBorder)
                Button("Copy"){copyText(text)}.disabled(text.isEmpty)
                if let path=state.log_paths?[service]{Button{NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath:path)])}label:{Image(systemName:"folder")}.help("Show log in Finder").accessibilityLabel("Show log in Finder")}
            }
            Divider()
            ScrollView([.vertical,.horizontal]){Text(text.isEmpty ? emptyDescription:text).font(.system(.caption,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)}
                .frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)
        }.padding(.horizontal,22).padding(.vertical,8)
    }
}
