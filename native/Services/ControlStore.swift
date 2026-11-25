import AppKit
import Foundation
import SwiftUI

struct Service: Decodable, Identifiable {
    let name:String, state:String, port:Int, pid:Int?, healthy:Bool
    let pids:[Int], listeners:[Int], identity:String?
    var id:String {name}
    var title:String {
        switch name {case "executor": "Shared Tunnel";case "executor-tunnel":"MCP Executor";default:"MCP Admin"}
    }
    var symbol:String {
        switch name {case "executor":"point.3.connected.trianglepath.dotted";case "executor-tunnel":"terminal";default:"lock.shield"}
    }
}
struct Project:Decodable,Identifiable {let project:String,kind:String,available:Bool;var id:String{project}}
struct Recovery:Decodable {let lease:String?,stale:Bool?,operations:Int,journals:Int,owned:Int,status:String}
struct Release:Decodable,Identifiable {let id:String,status:String,version:String}
struct Snapshot:Decodable {
    let overall:String,issues:[String],workspace:String,installation:String,version:String?,schema:String?,source:String?
    let components:[Service],projects:[Project],recovery:[String:Recovery],releases:[Release],activity:[String],logs:[String:[String]]
    let service_identity:String?,log_paths:[String:String]?
    var allOff:Bool {components.allSatisfy{$0.pids.isEmpty && $0.listeners.isEmpty}}
    var allReady:Bool {components.allSatisfy(\.healthy)}
    var busyWork:Bool {recovery.values.contains{$0.lease != nil || $0.journals>0 || $0.owned>0 || $0.operations>0}}
    var statusTitle:String {
        if !issues.isEmpty {return components.first?.healthy==true ? "Installation degraded":"Installation needs repair"}
        if overall=="Recovery required" {return overall}
        if allOff {return "Stopped"}
        if allReady {return "Fully operational"}
        if let first=components.first(where:{!$0.healthy}) {return first.title+(first.state=="Ownership conflict" ? " has a conflict":" unavailable")}
        return overall
    }
}
struct ControlFailure:LocalizedError {let message:String;var errorDescription:String?{message}}
enum ControlClient {
    static var root:URL {
        if let override=ProcessInfo.processInfo.environment["CHATGPT_MCP_CONTROL_ROOT"] {return URL(fileURLWithPath:override,isDirectory:true)}
        let relative=Bundle.main.object(forInfoDictionaryKey:"MCPInstallDirectory") as? String ?? "ChatGPT/LedgerForge-MCP"
        return Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent(relative,isDirectory:true).standardizedFileURL
    }
    static func run(_ args:[String]) async throws -> Data {
        let native=["catalog","inspect","apply","preferences"].contains(args.first ?? "")
        let helper=native ? Bundle.main.url(forResource:"maintenance",withExtension:"py") : root.appendingPathComponent("mcp_control.py")
        guard let helper,FileManager.default.isReadableFile(atPath:helper.path) else {throw ControlFailure(message:"Missing local control helper. Inspect the installation in Settings.")}
        let prefix=native ? [helper.path,root.path]:[helper.path]
        return try await Task.detached(priority:.userInitiated){
            let proc=Process(),pipe=Pipe()
            proc.executableURL=URL(fileURLWithPath:"/usr/bin/python3");proc.arguments=["-B"]+prefix+args
            proc.standardInput=FileHandle.nullDevice;proc.standardOutput=pipe;proc.standardError=pipe
            try proc.run();let data=pipe.fileHandleForReading.readDataToEndOfFile();proc.waitUntilExit()
            guard proc.terminationStatus==0 else {
                let obj=(try? JSONSerialization.jsonObject(with:data)) as? [String:Any]
                throw ControlFailure(message:obj?["error"] as? String ?? String(decoding:data.suffix(900),as:UTF8.self))
            }
            return data
        }.value
    }
    static func get<T:Decodable>(_ type:T.Type,_ args:[String]) async throws -> T {
        try JSONDecoder().decode(type,from:try await run(args))
    }
}
struct ObjectAction:Decodable,Identifiable {let name:String,label:String,impact:String;var id:String{name}}
struct ManagedObject:Decodable,Identifiable {
    let kind:String,id:String,title:String,status:String,project:String,identity:String,details:[String],actions:[ObjectAction],path:String?
}
struct PortConfig:Decodable {let ports:[String:Int],identity:String,pending:Bool}
struct ControlAction:Identifiable {
    var id=UUID();let title:String,detail:String,args:[String];var isLease:Bool=false
}
enum SectionKind:String,CaseIterable,Identifiable {
    case projects="Projects",leases="Leases",work="Processes & Validations",releases="Releases",rollback="Rollback",cleanup="Cleanup"
    var id:String{rawValue}
    var key:String{switch self {case .projects:"projects";case .leases:"leases";case .work:"work";case .releases:"releases";case .rollback:"rollback";case .cleanup:"cleanup"}}
}
@MainActor
final class ControlStore:ObservableObject {
    @Published var state:Snapshot?
    @Published var tab=0
    @Published var busy=false
    @Published var refreshInFlight=false
    @Published var error:String?
    @Published var notice:String?
    @Published var phase:String?
    @Published var section:SectionKind = .leases
    @Published var confirmation:ControlAction?
    @Published var diagnostics:String?
    @Published var selectionRequest:String?
    @Published var revision=0
    func applyAppearance(){
        let style=UserDefaults.standard.string(forKey:"appearance") ?? "System"
        NSApp.appearance=style=="System" ? nil:NSAppearance(named:style=="Dark" ? .darkAqua:.aqua)
    }
    func refresh() async {
        guard !refreshInFlight,!busy else{return};refreshInFlight=true
        defer{refreshInFlight=false}
        do {state=try await ControlClient.get(Snapshot.self,["status"]);error=nil}
        catch {state=nil;self.error=error.localizedDescription}
    }
    func loginStartup() async {
        await refresh()
        guard let s=state,s.issues.isEmpty,!s.busyWork,!s.allReady else{return}
        await perform(["start"],"Starting services at login")
    }
    func explore(_ kind:SectionKind,_ key:String?=nil){section=kind;selectionRequest=key;tab=3;revision+=1}
    func ask(_ title:String,_ detail:String,_ args:[String],lease:Bool=false){confirmation=ControlAction(title:title,detail:detail,args:args,isLease:lease)}
    func perform(_ args:[String],_ title:String) async {
        guard !busy else{return};busy=true;error=nil;notice=nil;phase=title
        var failure:String?
        do {
            let data=try await ControlClient.run(args)
            let obj=(try? JSONSerialization.jsonObject(with:data)) as? [String:Any] ?? [:]
            if args.first=="diagnose-connection" {
                let keys=[("connection","Connection"),("profile","Profile"),("port","Local port"),("pid","PID"),("healthz","Health endpoint"),("readyz","Ready endpoint"),("local_scope_verified","Local credential"),("shared_executor","Shared Tunnel")]
                diagnostics=keys.map{label in
                    let value=obj[label.0]
                    if let b=value as? NSNumber,CFGetTypeID(b)==CFBooleanGetTypeID(){return label.1+" · "+(b.boolValue ? "Verified":"Unavailable")}
                    return label.1+" · "+(value==nil || value is NSNull ? "Unavailable":String(describing:value!))
                }.joined(separator:"\n")+"\n\n"+((obj["log"] as? [String]) ?? []).joined(separator:"\n")
            } else if args.first=="verify" {notice="Schema verified · "+String(describing:obj["tools"] ?? "–")+" tools · "+String(describing:obj["version"] ?? "–")}
            else if let result=obj["verified"] as? String {notice=result}
            else if let rid=obj["release_id"] as? String,obj["result"] as? String=="deployed"{notice="Deployment verified · "+rid}
            else {notice=title+" · verified"}
        } catch {failure=error.localizedDescription}
        phase="Verifying current state…";busy=false
        await refresh();revision+=1;phase=nil
        if let failure {error=failure;notice=nil}
    }
}
