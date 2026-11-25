import Foundation
import Darwin

enum LoginItem {
    static let id = "local.chatgpt.mcp.control"
    static let file = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/"+id+".plist")
    static var enabled:Bool {
        guard let data=try? Data(contentsOf:file), let dict=try? PropertyListSerialization.propertyList(from:data,format:nil) as? [String:Any] else {return false}
        return dict["Label"] as? String==id && (dict["ProgramArguments"] as? [String])?.first==Bundle.main.executableURL?.path
    }
    static func launchctl(_ args:[String])throws->(Int32,String) {
        let proc=Process();let pipe=Pipe()
        proc.executableURL=URL(fileURLWithPath:"/bin/launchctl");proc.arguments=args;proc.standardOutput=pipe;proc.standardError=pipe
        try proc.run();let bytes=pipe.fileHandleForReading.readDataToEndOfFile();proc.waitUntilExit()
        return (proc.terminationStatus,String(decoding:bytes,as:UTF8.self))
    }
    static func set(_ enable:Bool)throws {
        let domain="gui/"+String(getuid())
        let service=domain+"/"+id
        let fm=FileManager.default
        if fm.fileExists(atPath:file.path) && !enabled {throw ControlFailure(message:"A different login item already uses this label. Inspect it in Login Items.")}
        if enable {
            guard let executable=Bundle.main.executableURL?.path else {throw ControlFailure(message:"Application executable unavailable.")}
            let plist:[String:Any]=["Label":id,"RunAtLoad":true,"LimitLoadToSessionType":"Aqua","ProgramArguments":[executable,"--background-login"]]
            try fm.createDirectory(at:file.deletingLastPathComponent(),withIntermediateDirectories:true)
            try PropertyListSerialization.data(fromPropertyList:plist,format:.xml,options:0).write(to:file,options:.atomic)
            let enabledResult=try launchctl(["enable",service])
            guard enabledResult.0==0 else {throw ControlFailure(message:enabledResult.1)}
            if try launchctl(["print",service]).0 != 0 {
                let result=try launchctl(["bootstrap",domain,file.path])
                guard result.0==0 else {throw ControlFailure(message:result.1)}
            }
        } else {
            let result=try launchctl(["disable",service])
            guard result.0==0 else {throw ControlFailure(message:result.1)}
            if fm.fileExists(atPath:file.path){try fm.removeItem(at:file)}
        }
        guard enabled==enable else {throw ControlFailure(message:"Login item preference did not persist.")}
    }
}
