import SwiftUI

private struct FeatureSettings:Decodable {let flags:[String:Bool],identity:String}
struct CapabilitySettings:View {
    @ObservedObject var control:ControlStore
    @State private var recorded:FeatureSettings?
    @State private var flags=[String:Bool]()
    @State private var problem:String?
    private let names=[("core","Core capability group"),("evidence","Evidence tools"),("optional","Optional project tools"),("ci_status_inspection","CI inspection preference")]
    var body:some View {
        WideDisclosure(title:"Executor capabilities"){
            ForEach(names,id:\.0){key,label in
                Toggle(label,isOn:Binding(get:{flags[key] ?? false},set:{flags[key]=$0})).disabled(recorded==nil)
            }
            Text("CI inspection also requires separately provisioned repository authorization.").font(.caption).foregroundStyle(.secondary)
            if let problem {Text(problem).font(.caption).foregroundStyle(.orange)}
            Button("Save capabilities…"){
                guard let recorded,let data=try? JSONEncoder().encode(flags) else{return}
                let changes=names.filter{flags[$0.0] != recorded.flags[$0.0]}.map{$0.1+" · "+(flags[$0.0]==true ? "On":"Off")}
                control.ask("Save capability settings",changes.joined(separator:"\n")+"\n\nThe executor reads these preferences on subsequent requests.",["preferences","save",String(decoding:data,as:UTF8.self),recorded.identity])
            }.disabled(recorded==nil || recorded?.flags==flags)
        }.task(id:control.revision){
            do {let v=try await ControlClient.get(FeatureSettings.self,["preferences","features"]);recorded=v;flags=v.flags;problem=nil}
            catch {problem=error.localizedDescription}
        }
    }
}
