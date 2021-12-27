open System
open System.Diagnostics
open System.Security.Cryptography
open System.Globalization
open System.Collections.Generic
open System.Text
open Akka.Actor
open Akka.FSharp

open FSharp.Data
open FSharp.Data.JsonExtensions
open FSharp.Json
open WebSocketSharp.Server


type Tweet_reply_info = {
    Type_of_Request : string
    Type : string
    Current_Status : string
    Description_info : string option
}

type Registration_reply_info = {
    Type_of_Request : string
    Type : string
    Current_Status : string
    Key_server : string
    Description_info : string option
}

type Registration_JSON = {
    Type_of_Request : string
    Users_ID : int
    Primary_username : string
    publicKey : string
}

type Tweet_marked = {
    JSON_unmakred: string
    H_Sign: string
}

type Users_tweet_info = {
    Type_of_Request : string
    Users_ID : int
    Tweets_ID : string
    Timestamp : DateTime
    Tweet_mssg_body : string
    HashTag_inTweet : string
    Mention_inTweet : int
    Retweet_count : int
}

type Reply_on_Tweet = {
    Type_of_Request : string
    Type : string
    Current_Status : int
    Users_tweet_info : Users_tweet_info
}

type Secondary_Info = {
    Type_of_Request : string
    Users_ID : int 
    Tweet_Owner_ID : int
}

type Secondary_Reply = {
    Type_of_Request : string
    Type : string
    Matched_TID : int
    Follower : int[]
    Owner : int[]
}

type Req_connection = {
    Type_of_Request : string
    Users_ID : int
    Sign_Info: string
}

type ReqConnect_reply_info = {
    Type_of_Request: string
    Type: string
    Current_Status: string
    Auth_header: string
    Description_info: string option
}

type DB_qInfo = {
    Type_of_Request : string
    Users_ID : int
    HashTag_inTweet : string
}

type Retweets_info = {
    Type_of_Request: string
    Users_ID : int
    Matched_TID : int
    Tweet_RID : string
}

type KeyInfo = {
    UserPublicKey: String
    SharedSecretKey: String
    ServerECDH: ECDiffieHellman
}

type ActorMsg = 
| WsockToActor of string * WebSocketSessionManager * string

type ConActorMsg =
| WebSocketToConnectionActor of string * WebSocketSessionManager * string
| AutoConnect of int

type RegActorMsg =
| WsockToRegActor of string * IActorRef * WebSocketSessionManager * string

type LoginActorMsg =
| WsockToLoginActor of string * IActorRef * WebSocketSessionManager * string

let print_OnConsole (printthisString:string) =
    printfn "\n<<<< %s >>>>\n" printthisString

let mutable is_debug_on = false

let stringToBytes (str: string) = 
    Text.Encoding.UTF8.GetBytes str

let create_chall =
    use rng = RNGCryptoServiceProvider.Create()
    let chall = Array.zeroCreate<byte> 32
    rng.GetBytes chall
    chall |> Convert.ToBase64String

let addByteTime (messge: byte[]) =
    let byteTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds() |> BitConverter.GetBytes
    Array.concat [|messge; byteTime|]

let hash256msg (messge: byte[]) = 
    messge |> SHA256.HashData 

let givePubKey (pubKey:byte[]) =
    let ecdiffHell = ECDiffieHellman.Create()
    let keySize = ecdiffHell.KeySize
    ecdiffHell.ImportSubjectPublicKeyInfo((System.ReadOnlySpan pubKey), (ref keySize))
    ecdiffHell.ExportParameters(false)
    
let check_sign (chall: string) (sgn: string) (key: string) =     
    let ans = chall |> Convert.FromBase64String |> addByteTime |> hash256msg
    let sgn = sgn.[0 .. 255] |> Convert.FromBase64String

    let pubKey = key |> Convert.FromBase64String
   
    let parms = pubKey |> givePubKey
    let ec = ECDsa.Create(parms)
    ec.VerifyData(ans, sgn, HashAlgorithmName.SHA256)

let givesecKey (ec: ECDiffieHellman) (key: String) = 
    let pubKey = key |> Convert.FromBase64String
    let keySize = ec.KeySize
    let ecdiffHell = ECDiffieHellman.Create()
    ecdiffHell.ImportSubjectPublicKeyInfo((System.ReadOnlySpan pubKey), (ref keySize))
    ec.DeriveKeyMaterial(ecdiffHell.PublicKey)


let check_hmac (jsonMessage:string) (sgn: string) (sharedSecretKey: byte[]) =
    use hmac = new HMACSHA1(sharedSecretKey)
    let calculatedSign = jsonMessage |> stringToBytes |> hmac.ComputeHash |> Convert.ToBase64String 
    if is_debug_on then
        printfn "Generating the server shared key using server's private key and user public key\n"
        printfn "\nUser's HMAC is: %A\nServer's generated HMAC is: %A\n" sgn calculatedSign
    sgn |> calculatedSign.Equals

let regMap = new Dictionary<int, Registration_JSON>()
let tweetMap = new Dictionary<string, Users_tweet_info>()
let historyMap = new Dictionary<int, List<string>>()
let tagMap = new Dictionary<string, List<string>>()
let pubMap = new Dictionary<int, List<int>>()
let subMap = new Dictionary<int, List<int>>()
let mentionMap = new Dictionary<int, List<string>>()
let keyMap = new Dictionary<int, KeyInfo>()

let challCacheMap = new Dictionary<int, String>()

let checkUserValidity usr_id = 
    (regMap.ContainsKey(usr_id)) 

let challCache (usr_id: int) (chall: string) =
    async{
        challCacheMap.Add(usr_id, chall)
        do! Async.Sleep 1000
        printfn "Challenge expired at timestamp -> %A " (DateTime.Now)
        challCacheMap.Remove(usr_id) |> ignore
    }
    

let updRegistrationMap (newInfo:Registration_JSON) =
    let usr_id = newInfo.Users_ID
    if not (regMap.ContainsKey(usr_id)) then
        regMap.Add(usr_id, newInfo)
        "Success"
    else
        "Fail"

let updKeyMap (newInfo:Registration_JSON) (ec: ECDiffieHellman)=
    keyMap.Add(
        newInfo.Users_ID,
        {
            UserPublicKey = newInfo.publicKey;
            SharedSecretKey = 
                (givesecKey ec newInfo.publicKey) |> Convert.ToBase64String;
            ServerECDH = ec;
        })

let updHistMap usr_id tw_idx =
    if usr_id >= 0 && (checkUserValidity usr_id) then        
        if not (historyMap.ContainsKey(usr_id)) then
            let newList = new List<string>()
            newList.Add(tw_idx)
            historyMap.Add(usr_id, newList)
        else
            if not (historyMap.[usr_id].Contains(tw_idx)) then
                (historyMap.[usr_id]).Add(tw_idx)
    
let updTagMap tag tw_idx = 
    if tag <> "" && tag.[0] = '#' then
        if not (tagMap.ContainsKey(tag)) then
            let newList = new List<string>()
            newList.Add(tw_idx)
            tagMap.Add(tag, newList)
        else
            (tagMap.[tag]).Add(tw_idx)

let updPublishSubMap pub_id sub_id = 
    let mutable failure = false
    if pub_id <> sub_id && (checkUserValidity pub_id) && (checkUserValidity sub_id) then
        if not (pubMap.ContainsKey(pub_id)) then
            let newList = new List<int>()
            newList.Add(sub_id)
            pubMap.Add(pub_id, newList)
        else
            if not ((pubMap.[pub_id]).Contains(sub_id)) then
                (pubMap.[pub_id]).Add(sub_id)
            else
                failure <- true

        if not (subMap.ContainsKey(sub_id)) then
            let newList = new List<int>()
            newList.Add(pub_id)
            subMap.Add(sub_id, newList)
        else
            if not ((subMap.[sub_id]).Contains(pub_id)) then
                (subMap.[sub_id]).Add(pub_id)
            else
                failure <- true
        if failure then
            "Fail"
        else
            "Success"
    else
        "Fail"

let updMenMap usr_id tw_idx =
    if usr_id >= 0 && (checkUserValidity usr_id) then
       if not (mentionMap.ContainsKey(usr_id)) then
            let newList = new List<string>()
            newList.Add(tw_idx)
            mentionMap.Add(usr_id, newList)
        else
            (mentionMap.[usr_id]).Add(tw_idx)

let updTwMap (newInfo:Users_tweet_info) =
    let tw_idx = newInfo.Tweets_ID
    let usr_id = newInfo.Users_ID
    let tag = newInfo.HashTag_inTweet
    let mention = newInfo.Mention_inTweet
    
    tweetMap.Add(tw_idx, newInfo)
    updHistMap usr_id tw_idx
    updTagMap tag tw_idx
    updMenMap mention tw_idx
    updHistMap mention tw_idx

    if (pubMap.ContainsKey(usr_id)) then
        for sub_id in (pubMap.[usr_id]) do
            updHistMap sub_id tw_idx

let updReTweetMsg usr_id (initTwDetail:Users_tweet_info) =
    let newTwDetail:Users_tweet_info = {
        Type_of_Request = initTwDetail.Type_of_Request ;
        Users_ID  = initTwDetail.Users_ID ;
        Tweets_ID = initTwDetail.Tweets_ID ;
        Timestamp = initTwDetail.Timestamp ;
        Tweet_mssg_body = initTwDetail.Tweet_mssg_body ;
        HashTag_inTweet = initTwDetail.HashTag_inTweet ;
        Mention_inTweet = initTwDetail.Mention_inTweet ;
        Retweet_count = (initTwDetail.Retweet_count+1) ;
    }
    tweetMap.[initTwDetail.Tweets_ID] <- newTwDetail
    updHistMap usr_id (initTwDetail.Tweets_ID)
    if (pubMap.ContainsKey(usr_id)) then
        for sub_id in (pubMap.[usr_id]) do
            updHistMap sub_id (initTwDetail.Tweets_ID)         

let addTwID (initTwDetail:Users_tweet_info) =
    let newTwDetail:Users_tweet_info = {
        Type_of_Request = initTwDetail.Type_of_Request;
        Users_ID  = initTwDetail.Users_ID;
        Tweets_ID = (tweetMap.Count + 1).ToString();
        Timestamp = initTwDetail.Timestamp;
        Tweet_mssg_body = initTwDetail.Tweet_mssg_body;
        HashTag_inTweet = initTwDetail.HashTag_inTweet;
        Mention_inTweet = initTwDetail.Mention_inTweet;
        Retweet_count = initTwDetail.Retweet_count;
    }
    newTwDetail

let giveTID (subpubMap:Dictionary<int, List<int>>) = 
    let mutable max_cnt = 0
    let mutable topID = -1 
    for entry in subpubMap do
        if entry.Value.Count > max_cnt then
            max_cnt <- (entry.Value.Count)
            topID <- entry.Key
    topID   
let giveTTag (tag_map:Dictionary<string, List<string>>) =
    let mutable max_cnt = 0
    let mutable tTag = ""
    for entry in tag_map do
        if entry.Value.Count > max_cnt then
            max_cnt <- (entry.Value.Count)
            tTag <- entry.Key
    tTag       
let giveTMention (mentionMap:Dictionary<int, List<string>>) =
    let mutable max_cnt = 0
    let mutable topMen = -1
    for entry in mentionMap do
        if entry.Value.Count > max_cnt then
            max_cnt <- (entry.Value.Count)
            topMen <- entry.Key
    topMen
let giveTRetweet (tweetMap:Dictionary<string, Users_tweet_info>) =
    let mutable max_cnt = 0
    let mutable top_retweet = ""
    for entry in tweetMap do
        if entry.Value.Retweet_count > max_cnt then
            max_cnt <- (entry.Value.Retweet_count)
            top_retweet <- entry.Key
    top_retweet

let displayMapInfo (display_info_mode:int) _ =
    if display_info_mode = 1 then
        let top_pub = giveTID pubMap
        let top_sub = giveTID subMap
        let tTag = giveTTag tagMap
        let top_men = giveTMention mentionMap
        let top_retweet = giveTRetweet tweetMap
                
        printfn "\n<<<<<<<<<<<<< Maps Status >>>>>>>>>>>>>>>>>"
        printfn "All Signed Up Users: %i" (regMap.Keys.Count)
        printfn " Tweets in Map: %i" (tweetMap.Keys.Count)
        if top_retweet <> "" then
            printfn "Tweet which is most retweeted: %s (%i)" top_retweet (tweetMap.[top_retweet].Retweet_count)
        if tTag <> "" then
            printfn "All types of tags: %i" (tagMap.Keys.Count)
            printfn "HashTag which is most used in Tweet: %s (%i)" tTag (tagMap.[tTag].Count)
        if top_men >= 0 then
            printfn "User which is mentioned most: User%i (%i)" top_men (mentionMap.[top_men].Count)
        if top_pub >= 0 then
            printfn "Author who has most subscribers: %i (%i subscribers)" top_pub (pubMap.[top_pub].Count)
        if top_sub >= 0 then
            printfn "Follower who has most subscribes: %i (%i subscribes)" top_sub (subMap.[top_sub].Count)
        printfn "------------------------------------------\n"

type QueryActorMsg = 
| WsockToQActor of string * IActorRef * WebSocketSessionManager * string


type QueryWorkerMsg =
| QueryHistory of string * WebSocketSessionManager * string * string[]
| QueryTag of string * WebSocketSessionManager * string * string[]
| QueryMention of string * WebSocketSessionManager * string * string[]

let qHistActor (serverMailbox:Actor<QueryActorMsg>) =
    let nodeName = serverMailbox.Self.Path.Name
    let rec loop() = actor {
        let! (message: QueryActorMsg) = serverMailbox.Receive()
        match message with
        | WsockToQActor (msg, workerRef ,session_man, sid) ->
            let queryInfo = (Json.deserialize<DB_qInfo> msg)
            let usr_id = queryInfo.Users_ID
            if not (historyMap.ContainsKey(usr_id)) then
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = queryInfo.Type_of_Request ;
                    Current_Status =  "NoTweet" ;
                    Description_info =  Some "Query done, there is no any Tweet to show yet" ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)
            else
                workerRef <! QueryHistory (msg, session_man, sid, historyMap.[usr_id].ToArray())
        return! loop()
    }
    loop() 

let qMenActor (serverMailbox:Actor<QueryActorMsg>) =
    let nodeName = serverMailbox.Self.Path.Name
    let rec loop() = actor {
        let! (message: QueryActorMsg) = serverMailbox.Receive()
        match message with
        | WsockToQActor (msg, workerRef ,session_man, sid) ->
            let queryInfo = (Json.deserialize<DB_qInfo> msg)
            let usr_id = queryInfo.Users_ID
            if not (mentionMap.ContainsKey(usr_id)) then
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = queryInfo.Type_of_Request ;
                    Current_Status =  "NoTweet" ;
                    Description_info =  Some "Query done, there is no any Tweet to show yet" ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)
            else
                workerRef <! QueryHistory (msg, session_man, sid, mentionMap.[usr_id].ToArray())
        return! loop()
    }
    loop() 

let qTagActor (serverMailbox:Actor<QueryActorMsg>) =
    let nodeName = serverMailbox.Self.Path.Name
    let rec loop() = actor {
        let! (message: QueryActorMsg) = serverMailbox.Receive()
        match message with
        | WsockToQActor (msg, workerRef ,session_man, sid) ->
            let queryInfo = (Json.deserialize<DB_qInfo> msg)
            let tag = queryInfo.HashTag_inTweet
            if not (tagMap.ContainsKey(tag)) then
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = queryInfo.Type_of_Request ;
                    Current_Status =  "NoTweet" ;
                    Description_info =  Some "Query done, there is no any Tweet to show yet" ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)
            else
                workerRef <! QueryHistory (msg, session_man, sid, tagMap.[tag].ToArray())
        return! loop()
    }
    loop() 

let qSubActor (serverMailbox:Actor<QueryActorMsg>) =
    let nodeName = serverMailbox.Self.Path.Name
    let rec loop() = actor {
        let! (message: QueryActorMsg) = serverMailbox.Receive()
        match message with
        | WsockToQActor (msg, _ ,session_man, sid) ->
            let queryInfo = (Json.deserialize<DB_qInfo> msg)
            let usr_id = queryInfo.Users_ID
            if not (subMap.ContainsKey(usr_id)) && not (pubMap.ContainsKey(usr_id))then
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "QueryHistory" ;
                    Current_Status =  "NoTweet" ;
                    Description_info =  Some ("User doesnt have subsribers nor does he subscribes ")  ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)
            else if (subMap.ContainsKey(usr_id)) && not (pubMap.ContainsKey(usr_id))then
                let srep:Secondary_Reply = {
                    Type_of_Request = "Reply" ;
                    Type = "ShowSub" ;
                    Matched_TID = usr_id ;
                    Follower = subMap.[usr_id].ToArray() ;
                    Owner = [||] ;
                }
                let data = (Json.serialize srep)
                session_man.SendTo(data,sid)
            else if not (subMap.ContainsKey(usr_id)) && (pubMap.ContainsKey(usr_id))then
                let srep:Secondary_Reply = {
                    Type_of_Request = "Reply" ;
                    Type = "ShowSub" ;
                    Matched_TID = usr_id ;
                    Follower = [||] ;
                    Owner = pubMap.[usr_id].ToArray() ;
                }
                let data = (Json.serialize srep)
                session_man.SendTo(data,sid)
            else 
                let srep:Secondary_Reply = {
                    Type_of_Request = "Reply" ;
                    Type = "ShowSub" ;
                    Matched_TID = usr_id ;
                    Follower = subMap.[usr_id].ToArray() ;
                    Owner = pubMap.[usr_id].ToArray() ;
                }
                let data = (Json.serialize srep)
                session_man.SendTo(data,sid)     
        return! loop()
    }
    loop() 


let qActorNode (mailbox:Actor<QueryWorkerMsg>) =
    let nodeName = "QueryActor " + mailbox.Self.Path.Name
    let rec loop() = actor {
        let! (message: QueryWorkerMsg) = mailbox.Receive()
       
        match message with
            | QueryHistory (json, session_man, sid, tweetIDarray) ->
                let  jsonMsg = JsonValue.Parse(json)
                let  usr_id = jsonMsg?Users_ID.AsInteger()
                
                let mutable tweetCount = 0
                for tw_idx in (tweetIDarray) do
                    if tweetMap.ContainsKey(tw_idx) then
                        tweetCount <- tweetCount + 1
                        let twRep:Reply_on_Tweet = {
                            Type_of_Request = "Reply" ;
                            Type = "ShowTweet" ;
                            Current_Status = tweetCount ;
                            Users_tweet_info = tweetMap.[tw_idx] ;
                        }
                        let data = (Json.serialize twRep)
                        session_man.SendTo(data,sid)

                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "QueryHistory" ;
                    Current_Status =  "Success" ;
                    Description_info =  Some "History fetched" ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)

            | QueryTag (json, session_man, sid, tweetIDarray) ->
                let  jsonMsg = JsonValue.Parse(json)
                let tag = jsonMsg?HashTag_inTweet.AsString()
                let mutable tweetCount = 0
                for tw_idx in tweetIDarray do
                    if tweetMap.ContainsKey(tw_idx) then
                        tweetCount <- tweetCount + 1
                        
                        let twRep:Reply_on_Tweet = {
                            Type_of_Request = "Reply" ;
                            Type = "ShowTweet" ;
                            Current_Status = tweetCount ;
                            Users_tweet_info = tweetMap.[tw_idx] ;
                        }
                        let data = (Json.serialize twRep)
                        session_man.SendTo(data,sid)

                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "QueryHistory" ;
                    Current_Status =  "Success" ;
                    Description_info =  Some ("Query Tweets with "+tag+ " finished") ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)

            | QueryMention (json, session_man, sid,tweetIDarray) ->
                let  jsonMsg = JsonValue.Parse(json)
                let  usr_id = jsonMsg?Users_ID.AsInteger()
                let  reqType = jsonMsg?Type_of_Request.AsString()
                let mutable tweetCount = 0
                for tw_idx in (tweetIDarray) do
                    if tweetMap.ContainsKey(tw_idx) then
                        tweetCount <- tweetCount + 1
                        let twRep:Reply_on_Tweet = {
                            Type_of_Request = "Reply" ;
                            Type = "ShowTweet" ;
                            Current_Status = tweetCount ;
                            Users_tweet_info = tweetMap.[tw_idx] ;
                        }
                        let data = (Json.serialize twRep)
                        session_man.SendTo(data,sid)

                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "QueryHistory" ;
                    Current_Status =  "Success" ;
                    Description_info =  Some " Tweets Query mentioned finished" ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)
        return! loop()
    }
    loop()

let regActor (serverMailbox:Actor<RegActorMsg>) =
    let nodeName = serverMailbox.Self.Path.Name
    let rec loop() = actor {
        let! (message: RegActorMsg) = serverMailbox.Receive()

        match message with
        | WsockToRegActor (msg, conn_actor, session_man, sid) ->
            let regMsg = (Json.deserialize<Registration_JSON> msg)
            let status = updRegistrationMap regMsg
            let serverECDH = ECDiffieHellman.Create()
            let serverPublicKey = 
                serverECDH.ExportSubjectPublicKeyInfo() |> Convert.ToBase64String            
                
            let retAns:Registration_reply_info = { 
                Type_of_Request = "Reply" ;
                Type = "Register" ;
                Current_Status =  status ;
                Key_server = serverPublicKey;
                Description_info = Some (regMsg.Users_ID.ToString());
            }
            let data = (Json.serialize retAns)
            session_man.SendTo(data,sid)

            if status = "Success" then
                if is_debug_on then
                    printfn "Create public key for user%i: %A" regMsg.Users_ID serverPublicKey
                    printfn "\n[%s] User public key saved and assigned it in map" nodeName
                updKeyMap regMsg serverECDH 
                conn_actor <! AutoConnect (regMsg.Users_ID)

        return! loop()
    }
    loop()     

let subscribeActor (serverMailbox:Actor<ActorMsg>) =
    let nodeName = serverMailbox.Self.Path.Name
    let rec loop() = actor {
        let! (message: ActorMsg) = serverMailbox.Receive()

        match message with
        | WsockToActor (msg, session_man, sid) ->
            let subInfo = (Json.deserialize<Secondary_Info> msg)
            let status = updPublishSubMap (subInfo.Tweet_Owner_ID) (subInfo.Users_ID)
            let mutable descStr = ""
            if status = "Success" then
                descStr <- "Successfully followed User " + (subInfo.Tweet_Owner_ID.ToString())
            else
                descStr <- "Failed to follow User " + (subInfo.Tweet_Owner_ID.ToString())

            let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "Subscribe" ;
                    Current_Status =  status ;
                    Description_info =  Some descStr ;
            }
            let data = (Json.serialize retAns)
            session_man.SendTo(data,sid)

        return! loop()
    }
    loop() 

let twActor (serverMailbox:Actor<ActorMsg>) =
    let nodeName = serverMailbox.Self.Path.Name
    let rec loop() = actor {
        let! (message: ActorMsg) = serverMailbox.Receive()

        match message with
        | WsockToActor (msg, session_man, sid) ->
            let m = (Json.deserialize<Tweet_marked> msg)
            let unsignedJson = m.JSON_unmakred
            let tInfo = Json.deserialize<Users_tweet_info> unsignedJson
            let sharedSecretKey = 
                keyMap.[tInfo.Users_ID].SharedSecretKey |> Convert.FromBase64String
            let tweetInfo = tInfo |> addTwID
            if not (checkUserValidity tweetInfo.Users_ID) then
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "SendTweet" ;
                    Current_Status =  "Failed" ;
                    Description_info =  Some "Before tweeting, sign up the user" ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)
            elif not (check_hmac unsignedJson m.H_Sign sharedSecretKey) then
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "SendTweet" ;
                    Current_Status =  "Failed" ;
                    Description_info =  Some "HMAC auth couldn't be passed" ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)
            else            
                updTwMap tweetInfo
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "SendTweet" ;
                    Current_Status =  "Success" ;
                    Description_info =  Some "Tweet to Server sent successfully" ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)            
                

        return! loop()
    }
    loop()

let reTwActor (serverMailbox:Actor<ActorMsg>) =
    let nodeName = serverMailbox.Self.Path.Name
    let rec loop() = actor {
        let! (message: ActorMsg) = serverMailbox.Receive()

        match message with
        | WsockToActor (msg, session_man, sid) ->
            let retweetInfo = (Json.deserialize<Retweets_info> msg)
            let reTwID = retweetInfo.Tweet_RID
            let usr_id = retweetInfo.Users_ID
            let tUserID = retweetInfo.Matched_TID
            let mutable failure = false

            if reTwID = "" then
                if (checkUserValidity tUserID) && historyMap.ContainsKey(tUserID) && historyMap.[tUserID].Count > 0 then
                    let rnd = Random()
                    let numTweet = historyMap.[tUserID].Count
                    let rndIdx = rnd.Next(numTweet)
                    let targetReTweetID = historyMap.[tUserID].[rndIdx]
                    let retweetInfo = tweetMap.[targetReTweetID]
                    if (retweetInfo.Users_ID <> usr_id) then
                        updReTweetMsg usr_id retweetInfo
                    else
                        failure <- true
                else
                    failure <- true
            else
                if tweetMap.ContainsKey(reTwID) then
                    if (tweetMap.[reTwID].Users_ID) <> usr_id then
                        updReTweetMsg usr_id (tweetMap.[reTwID])
                    else
                        failure <- true
                else
                    failure <- true

            if failure then
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "SendTweet" ;
                    Current_Status =  "Failed" ;
                    Description_info =  Some "Author rule violated or cant find tweetID. Hence, retweet failed." ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)
            else
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = "SendTweet" ;
                    Current_Status =  "Success" ;
                    Description_info =  Some "Retweeting Tweet finished successfully" ;
                }
                let data = (Json.serialize retAns)
                session_man.SendTo(data,sid)

        return! loop()
    }
    loop()

let twSystem = ActorSystem.Create("TwServer")

let totalQWorker = 1000

let createQActors (num: int) = 
    [1 .. num]
    |> List.map (fun ind -> (spawn twSystem ("Q"+ind.ToString()) qActorNode))
    |> List.toArray
let qWorker = createQActors totalQWorker

let giveRandWorker () =
    let rand = Random()
    qWorker.[rand.Next(totalQWorker)]

let mutable onUsers = Set.empty

let updOnUsrDatabase usr_id opt = 
    let checkConnect = onUsers.Contains(usr_id)
    if opt = "connect" && not checkConnect then
        if checkUserValidity usr_id then
            onUsers <- onUsers.Add(usr_id)
            0
        else
            -1
    else if opt = "disconnect" && checkConnect then
        onUsers <- onUsers.Remove(usr_id)
        0
    else
        0

let connActor (serverMailbox:Actor<ConActorMsg>) =
    let rec loop() = actor {

        let! (messge: ConActorMsg) = serverMailbox.Receive()
        match messge with
        | WebSocketToConnectionActor (messge, session_man, sid) ->
            let conn_info = (Json.deserialize<Req_connection> messge)
            let usr_id = conn_info.Users_ID
            let request_typ = conn_info.Type_of_Request           
            
            match request_typ with
            | "Connect" ->
                if not (onUsers.Contains(usr_id)) && checkUserValidity usr_id then
                    let chall = create_chall
                    challCache usr_id chall |> Async.Start
                    if is_debug_on then
                        printfn "Generate 256 bit challenge: %A\n We will cache this challenge for 1 sec" chall
                        printfn "Timestamp -> %A\n" (DateTime.Now)
                    let (retAns:ReqConnect_reply_info) = { 
                        Type_of_Request = "Reply" ;
                        Type = request_typ ;
                        Current_Status =  "Auth" ;
                        Auth_header = chall;
                        Description_info =  Some (usr_id.ToString());
                    }
                    let jsondata = (Json.serialize retAns)
                    session_man.SendTo(jsondata,sid)  
                else 
                    let (retAns:ReqConnect_reply_info) = { 
                        Type_of_Request = "Reply" ;
                        Type = request_typ ;
                        Current_Status =  "Fail" ;
                        Auth_header = "";
                        Description_info =  Some ("Signup required") ;
                    }
                    let jsondata = (Json.serialize retAns)
                    session_man.SendTo(jsondata,sid)                         
            | "Auth" ->
                let key_data = keyMap.[usr_id]
                if (challCacheMap.ContainsKey usr_id) then
                    let res = challCacheMap.[usr_id]
                    let sgn = conn_info.Sign_Info
                    if is_debug_on then
                        printfn "Server received auth mssg from user at %A" DateTime.Now
                        printfn "Verify the recieved user's public key with the cached challenge... "
                    if (check_sign res sgn key_data.UserPublicKey) then
                        let (retAns:ReqConnect_reply_info) = { 
                            Type_of_Request = "Reply" ;
                            Type = request_typ ;
                            Current_Status =  "Success" ;
                            Auth_header = "";
                            Description_info =  Some (usr_id.ToString());
                        }
                        let jsondata = (Json.serialize retAns)
                        session_man.SendTo(jsondata,sid)
                    else
                        printfn "\nUser %i auth failed\n" usr_id
                        let (retAns:ReqConnect_reply_info) = { 
                            Type_of_Request = "Reply" ;
                            Type = request_typ ;
                            Current_Status =  "Fail" ;
                            Description_info =  Some "Authentication failed!" ;
                            Auth_header = "";
                        }
                        let jsondata = (Json.serialize retAns)
                        session_man.SendTo(jsondata,sid)
                else
                    let (retAns:ReqConnect_reply_info) = { 
                        Type_of_Request = "Reply" ;
                        Type = request_typ ;
                        Current_Status =  "Fail" ;
                        Description_info =  Some "Auth failure!" ;
                        Auth_header = "";
                    }
                    let jsondata = (Json.serialize retAns)
                    session_man.SendTo(jsondata,sid)
            | _ ->
                (updOnUsrDatabase usr_id "disconnect") |> ignore
                let (retAns:Tweet_reply_info) = { 
                    Type_of_Request = "Reply" ;
                    Type = request_typ ;
                    Current_Status =  "Success" ;
                    Description_info =   Some (usr_id.ToString()) ;
                }
                let jsondata = (Json.serialize retAns)
                session_man.SendTo(jsondata,sid)
        | AutoConnect usr_id ->
            let ret = updOnUsrDatabase usr_id "connect"
            if ret< 0 then printfn "Failed to connect User %i to server" usr_id
            else printfn "User %i connected to server successfully!" usr_id

        return! loop()
    }
    loop() 

let websocketServer = WebSocketServer("ws://localhost:9001")

let register_actor = spawn twSystem "SignUp_Databse_Actor" regActor
let tw_actor = spawn twSystem "Tweet_Databse_Actor" twActor
let rtw_actor = spawn twSystem "Retweet_Databse_Actor" reTwActor
let subs_actor = spawn twSystem "Subs_Databse_Actor" subscribeActor
let conn_actor = spawn twSystem "Conn_Databse_Actor" connActor
let qu_hist_actor = spawn twSystem "QHist_Databse_Actor" qHistActor
let qu_men_actor = spawn twSystem "QMen_Databse_Actor" qMenActor
let qu_tag_actor = spawn twSystem "QTag_Databse_Actor" qTagActor
let qu_sub_actor = spawn twSystem "QSub_Databse_Actor" qSubActor

type Disconnect () =
    inherit WebSocketBehavior()
    override x.OnMessage message = 
        printfn "Server rx: [Disconnect] %s" message.Data 
        printfn "ID: %A" x.ID
        printfn "Session: %A" x.Sessions.IDs
        x.Send (message.Data + " [from server]")

type SignUp () =
    inherit WebSocketBehavior()
    override wssm.OnMessage messge = 
        printfn "\n[/register]\nData:%s\n" messge.Data 
        register_actor <! WsockToRegActor (messge.Data, conn_actor, wssm.Sessions, wssm.ID)

type Tweet () =
    inherit WebSocketBehavior()
    override wssm.OnMessage messge = 
        printfn "\n[/tweet/send]\nData:%s\n" messge.Data 
        tw_actor <! WsockToActor (messge.Data, wssm.Sessions, wssm.ID)

type Retweet () =
    inherit WebSocketBehavior()
    override wssm.OnMessage messge = 
        printfn "\n[/tweet/retweet]\nData:%s\n"  messge.Data 
        rtw_actor <! WsockToActor (messge.Data, wssm.Sessions, wssm.ID)

type Subscribe () =
    inherit WebSocketBehavior()
    override wssm.OnMessage messge = 
        printfn "\n[/subscribe]\nData:%s\n" messge.Data 
        subs_actor <! WsockToActor (messge.Data,wssm.Sessions,wssm.ID)

type Connection () =
    inherit WebSocketBehavior()
    override wssm.OnMessage messge = 
        printfn "\n[/connection]\nData:%s\n" (messge.Data)
        conn_actor <! WebSocketToConnectionActor (messge.Data,wssm.Sessions,wssm.ID)

type QHistory () =
    inherit WebSocketBehavior()
    override wssm.OnMessage messge = 
        printfn "\n[/tweet/query]\nData:%s\n" messge.Data
        qu_hist_actor <! WsockToQActor (messge.Data, giveRandWorker(), wssm.Sessions, wssm.ID)

type QMention () =
    inherit WebSocketBehavior()
    override wssm.OnMessage messge = 
        printfn "\n[/mention/query]\nData:%s\n" messge.Data
        qu_men_actor <! WsockToQActor (messge.Data, giveRandWorker(), wssm.Sessions, wssm.ID)

type QTag () =
    inherit WebSocketBehavior()
    override wssm.OnMessage messge = 
        printfn "\n[/tag/query]\nData:%s\n" messge.Data
        qu_tag_actor <! WsockToQActor (messge.Data, giveRandWorker(), wssm.Sessions, wssm.ID)
type QSub () =
    inherit WebSocketBehavior()
    override wssm.OnMessage messge = 
        printfn "\n[/subscribe/query]\nData:%s\n" messge.Data
        qu_sub_actor <! WsockToQActor (messge.Data, giveRandWorker() , wssm.Sessions, wssm.ID)

[<EntryPoint>]
let main argv =
    try
        if argv.Length <> 0 then
            is_debug_on <- 
                match (argv.[0]) with
                | "tester" -> true
                | _ -> false

        websocketServer.AddWebSocketService<SignUp> ("/register")
        websocketServer.AddWebSocketService<Tweet> ("/tweet/send")
        websocketServer.AddWebSocketService<Retweet> ("/tweet/retweet")
        websocketServer.AddWebSocketService<Subscribe> ("/subscribe")
        websocketServer.AddWebSocketService<Connection> ("/login")
        websocketServer.AddWebSocketService<Connection> ("/logout")
        websocketServer.AddWebSocketService<QHistory> ("/tweet/query")
        websocketServer.AddWebSocketService<QMention> ("/mention/query")
        websocketServer.AddWebSocketService<QTag> ("/hashtag_var/query")
        websocketServer.AddWebSocketService<QSub> ("/subscribe/query")
        websocketServer.Start ()
        if is_debug_on then
            printfn "\n<<<<< Twitter server start with tester mode.... >>>>> \n"
        else
            printfn "<<<<< Twitter server start.... >>>>> \n"
        Console.ReadLine() |> ignore
        websocketServer.Stop()
 

    with | :? IndexOutOfRangeException ->
            printfn "\nNot correct Inputs or Index out of range !\n"

         | :?  FormatException ->
            printfn "\n FormatException error!\n"
    0
