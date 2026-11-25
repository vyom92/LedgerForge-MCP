import SwiftUI
import AppKit

struct MaintenanceView:View {
    @ObservedObject var control:ControlStore
    @State private var rows=[ManagedObject]()
    @State private var detail:ManagedObject?
    @State private var loading=false
    @State private var warning:String?
    @State private var manual=""
    @State private var filter=""
    @State private var request=UUID()
    @State private var connections=false
    var body:some View {
        VStack(alignment:.leading,spacing:8){
            WideDisclosure(title:"Service controls and diagnostics"){
                if let s=control.state {ForEach(s.components){row in
                    HStack{Text(row.title).frame(width:105,alignment:.leading)
                        if row.healthy {
                            Button("Stop"){askConnection("stop",row)}.accessibilityLabel("Stop "+row.title)
                            Button("Restart"){askConnection("restart",row)}.accessibilityLabel("Restart "+row.title)
                        } else if row.pids.isEmpty && row.listeners.isEmpty {Button("Start"){runConnection("start",row)}.accessibilityLabel("Start "+row.title)}
                        if row.name != "executor" {Button("Repair"){repair(row,control:control)}.accessibilityLabel("Repair "+row.title);Button("Diagnostics"){runConnection("diagnose",row)}.accessibilityLabel("Diagnostics "+row.title)}
                        else {Button("Repair"){repair(row,control:control)}.accessibilityLabel("Repair "+row.title);Button("Verify schema"){Task{await control.perform(["verify"],"Verify schema")}}.disabled(!row.healthy)}
                    }.controlSize(.small)
                }}
            }
            HStack{Picker("Inspect",selection:$control.section){ForEach(SectionKind.allCases){Text($0.rawValue).tag($0)}}.fixedSize()
                TextField("Filter records",text:$filter).textFieldStyle(.roundedBorder)
                Button {Task{await load(preferred:detail?.id)}} label:{Image(systemName:"arrow.clockwise")}.accessibilityLabel("Refresh records")
            }
            if let warning{Text(warning).foregroundStyle(.orange).textSelection(.enabled)}
            Divider()
            HSplitView {
                ScrollView {
                    LazyVStack(alignment:.leading,spacing:3){
                        ForEach(rows.filter{filter.isEmpty || ($0.title+" "+$0.project+" "+$0.id).localizedCaseInsensitiveContains(filter)}){r in
                            Button{Task{await choose(r.id)}}label:{
                                VStack(alignment:.leading,spacing:3){Text(r.title).font(.callout.weight(.medium)).lineLimit(2)
                                    Text([r.project,r.status].filter{!$0.isEmpty}.joined(separator:" · ")).font(.caption).foregroundStyle(.secondary).lineLimit(2)}
                                    .frame(maxWidth:.infinity,alignment:.leading).padding(.horizontal,8).padding(.vertical,7).contentShape(Rectangle())
                            }.buttonStyle(.plain).background(detail?.id==r.id ? Color.accentColor.opacity(0.17):.clear,in:RoundedRectangle(cornerRadius:6))
                        }
                    }
                    if rows.isEmpty && !loading && warning==nil{Text("No records found.").foregroundStyle(.secondary).padding(8)}
                }.frame(minWidth:170,idealWidth:220,maxWidth:270)
                ScrollView{
                    VStack(alignment:.leading,spacing:10){
                        if let d=detail {
                            Text(d.title).font(.title3.bold()).textSelection(.enabled)
                            Text(d.status).font(.subheadline.bold()).foregroundStyle(.secondary)
                            ForEach(d.actions){a in Button(a.label){invoke(d,a)}}
                            let split=d.details.firstIndex(of:"Recent log") ?? d.details.endIndex
                            ForEach(Array(d.details[..<split].enumerated()),id:\.offset){_,text in Text(text).font(.callout).textSelection(.enabled)}
                            if split<d.details.endIndex {
                                WideDisclosure(title:"Recent log"){
                                    Text(d.details.dropFirst(split+1).joined(separator:"\n")).font(.caption.monospaced()).textSelection(.enabled)
                                }
                            }
                            if d.actions.isEmpty && [.leases,.releases,.rollback,.cleanup].contains(control.section) {Text("No action is currently eligible.").font(.caption).foregroundStyle(.secondary)}
                            WideDisclosure(title:"Record details"){
                                Text(d.id).font(.caption.monospaced()).textSelection(.enabled)
                                if let p=d.path{Text(p).font(.caption.monospaced()).textSelection(.enabled)}
                            }
                            HStack{Button("Copy summary"){copyText(([d.title,d.status]+d.details).joined(separator:"\n"))}
                                if let p=d.path{Button("Show in Finder"){NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath:p)])}}
                            }.controlSize(.small)
                        } else {Text(loading ? "Reading local records…":"Select a record to inspect it.").foregroundStyle(.secondary)}
                    }.frame(maxWidth:.infinity,alignment:.leading).padding(.horizontal,12).padding(.vertical,5)
                }.frame(minWidth:250,maxWidth:.infinity)
            }.frame(maxWidth:.infinity,maxHeight:.infinity)
            Divider()
            WideDisclosure(title:"Advanced lookup by identifier"){
                HStack{TextField(control.section == .projects ? "Workspace-relative project":"Exact identifier",text:$manual)
                        .textFieldStyle(.roundedBorder).onSubmit{Task{await choose(manual)}}
                    Button("Look up"){Task{await choose(manual)}}.disabled(manual.isEmpty)}
            }
        }.padding(.horizontal,22).padding(.vertical,5).disabled(control.busy)
        .task(id:control.section){filter="";manual="";detail=nil;await load(preferred:control.selectionRequest)}
        .onChange(of:control.revision){_,_ in Task{await load(preferred:control.selectionRequest ?? detail?.id)}}
    }
    func load(preferred:String?) async {
        let key=control.section.key;let ticket=UUID();request=ticket;loading=true;warning=nil;detail=nil
        do {
            let values=try await ControlClient.get([ManagedObject].self,["catalog",key])
            guard ticket==request,key==control.section.key else{return}
            rows=values;loading=false
            if let target=preferred ?? values.first?.id {control.selectionRequest=nil;await choose(target)}
            else{detail=nil}
        }catch {guard request==ticket else{return};detail=nil;rows=[];loading=false;warning=error.localizedDescription}
    }
    func choose(_ id:String) async {
        let key=control.section.key;let ticket=UUID();request=ticket;warning=nil;loading=true;detail=nil
        do{let selected=try await ControlClient.get(ManagedObject.self,["inspect",key,id])
            guard ticket==request,key==control.section.key else{return};detail=selected;loading=false
        }catch{guard ticket==request else{return};detail=nil;loading=false;warning=error.localizedDescription}
    }
    func invoke(_ obj:ManagedObject,_ a:ObjectAction){
        guard !loading,detail?.identity==obj.identity else{return}
        let args=["apply",obj.kind,obj.id,obj.identity,a.name]
        if a.name=="qualify"{Task{await control.perform(args,"Qualifying "+obj.title)}}
        else {control.ask(a.label,obj.title+" · "+obj.status+"\n\n"+a.impact,args,lease:obj.kind=="leases")}
    }
    func runConnection(_ verb:String,_ row:Service){
        let op=row.name=="executor" ? verb:verb+"-connection"
        Task{await control.perform([op,row.name]+(verb=="diagnose" ? []:serviceCondition(row.identity)),verb.capitalized+" "+row.title)}
    }
    func askConnection(_ verb:String,_ row:Service){
        let op=row.name=="executor" ? verb:verb+"-connection"
        let affected=row.name=="executor" ? "Both connections depend on this backend. Active execution prevents interruption.":"Only this profile will be interrupted. The opposite connection and Shared Tunnel keep running."
        control.ask(verb.capitalized+" "+row.title,affected,[op,row.name]+serviceCondition(row.identity))
    }
}
struct ConfirmAction:View {
    let action:ControlAction
    @ObservedObject var control:ControlStore
    @Environment(\.dismiss) var dismiss
    @State private var terminate=false
    @State private var kill=false
    @State private var stale=false
    @State private var all=false
    @State private var restart=true
    var body:some View {
        VStack(alignment:.leading,spacing:13){
            Text(action.title).font(.title2.bold())
            Text(action.detail).textSelection(.enabled)
            if action.isLease{
                Toggle("Restart Shared Tunnel after recovery",isOn:$restart)
                WideDisclosure(title:"Advanced recovery options"){
                    Toggle("Terminate verified owned processes",isOn:$terminate)
                    Toggle("Force termination after timeout",isOn:$kill)
                    Toggle("Reconcile stale non-journal operations",isOn:$stale)
                    Toggle("Stop all exact executor instances",isOn:$all)
                }
            }
            HStack{Spacer();Button("Cancel"){dismiss()}.keyboardShortcut(.cancelAction)
                Button(action.title){
                    var args=action.args
                    if action.isLease{
                        if restart{args.append("--restart")};if terminate{args.append("--terminate-owned")};if kill{args.append("--kill-after-timeout")}
                        if stale{args.append("--allow-stale-nonjournal-ops")};if all{args.append("--all-exact-executors")}
                    }
                    dismiss();Task{await control.perform(args,action.title)}
                }.buttonStyle(.borderedProminent)
            }
        }.padding(22).frame(width:434)
    }
}
