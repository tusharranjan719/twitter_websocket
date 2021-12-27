open System
open System.Security.Cryptography
open System.Globalization
open System.Text
open System.Collections.Generic
open Akka.Actor
open Akka.FSharp
open System.Diagnostics
open FSharp.Data
open FSharp.Data.JsonExtensions
open FSharp.Json
open WebSocketSharp

type CheckStatusforUser =
| Success
| Fail
| Waiting
| Timeout
| SessionTimeout

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

let print_OnConsole (printthisString:string) =
    printfn "\n<<<< %s >>>>\n" printthisString

let system = ActorSystem.Create("UserInterface")
let webSocket_Server_adrs = "ws://localhost:9001"
let universal_timer = Stopwatch()

let mutable AuthFlag_debug = false
let mutable (serv_pub_key:string) = ""
let mutable (checkifUserLogin_success:CheckStatusforUser) = Waiting

let convert_stringBytes (inputstr: string) = 
    Text.Encoding.UTF8.GetBytes inputstr

let intro_time_paddingdelay (message: byte[]) =
    let current_clock_time = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
    let pad_amount = current_clock_time |> BitConverter.GetBytes
    if AuthFlag_debug then
         printfn "Introduce time padding to message:\ncurrent time:%i (unix seconds)\n" current_clock_time 
    Array.concat [|message; pad_amount|]

let get_hash_data (message: byte[]) = 
    message |> SHA256.HashData 

let ECkeyPublic (public_bytes:byte[]) =
    let hellman_var = ECDiffieHellman.Create()
    let size = hellman_var.KeySize
    hellman_var.ImportSubjectPublicKeyInfo((System.ReadOnlySpan public_bytes), (ref size))
    hellman_var.ExportParameters(false)

let authSignFetch (message: byte[]) (hellman_var: ECDiffieHellman) =
    let ecdsa = hellman_var.ExportParameters(true) |> ECDsa.Create
    let enc_hash_mssg = message |> intro_time_paddingdelay |> get_hash_data
    if AuthFlag_debug then
        printfn "Encrypted : %A" (enc_hash_mssg|>Convert.ToBase64String)
    ecdsa.SignData(enc_hash_mssg, HashAlgorithmName.SHA256) |> Convert.ToBase64String

let findSecretkey_shared (clientECDH: ECDiffieHellman) (publicKey: String) = 
    let public_bytes = publicKey |> Convert.FromBase64String
    let size = clientECDH.KeySize
    let temp = ECDiffieHellman.Create()
    temp.ImportSubjectPublicKeyInfo((System.ReadOnlySpan public_bytes), (ref size))
    clientECDH.DeriveKeyMaterial(temp.PublicKey)

let signHMAC (jsonMessage: string) (sharedSecretKey: byte[]) =    
    use hmac_var = new HMACSHA1(sharedSecretKey)
    jsonMessage |> convert_stringBytes |> hmac_var.ComputeHash |> Convert.ToBase64String

let askInput (option:string) = 
    let mutable store_prom = true
    let mutable enteredString = ""
    match option with
    | "int" ->
        while store_prom do
            printf "(int): "
            enteredString <- Console.ReadLine()
            match (Int32.TryParse(enteredString)) with
            | (true, _) -> (store_prom <- false)
            | (false, _) ->  printfn "Please enter a valid number!"
        enteredString
    | "string" ->
        while store_prom do
            printf "(string): "
            enteredString <- Console.ReadLine()
            match enteredString with
            | "" | "\n" | "\r" | "\r\n" | "\0" -> printfn "Enter a valid string!"
            | _ -> (store_prom <- false)
        enteredString
    | "YesNo" ->
        while store_prom do
            printf "(yes/no): "
            enteredString <- Console.ReadLine()
            match enteredString.ToLower() with
            | "yes" | "y" -> 
                (store_prom <- false) 
                enteredString<-"yes"
            | "no" | "n" ->
                (store_prom <- false) 
                enteredString<-"no"
            | _ -> printfn "Enter either yes or no only!"
        enteredString
    | _ ->
        enteredString                                
    
let regJSON_output (publicKey:string) =
    printfn "Hello! Enter your unique user id: "
    let user_id = (int) (askInput "int")
    printfn "Enter your name: "
    let username = (askInput "string")
    let regJSON:Registration_JSON = { 
        Type_of_Request = "Register" ; 
        Users_ID =  user_id ;
        Primary_username = username ; 
        publicKey = publicKey;
    }
    Json.serialize regJSON

let reqCnDjson (option:string, user_currentID:int) = 
    if option = "Connect" then
        printfn "Welcome back! Enter your unique user id:  "
        let user_id = (int) (askInput "int")
        let estJSON:Req_connection = {
            Type_of_Request = "Connect" ;
            Users_ID = user_id;
            Sign_Info = "";
        }
        Json.serialize estJSON
    else
        let estJSON:Req_connection = {
            Type_of_Request = "Disconnect" ;
            Users_ID = user_currentID ;
            Sign_Info = "";
        }
        Json.serialize estJSON

let Tweet_infoJSON user_currentID = 
    let mutable hashtag_var = ""
    let mutable mention = -1
    printfn "Enter tweet message: "
    let content = (askInput "string")
    printfn "Do you want add #hashtags? "
    if (askInput "YesNo") = "yes" then
        printfn "Enter hashtag (with #): "
        hashtag_var <- (askInput "string")
    printfn "Do you want add @mentions? "
    if (askInput "YesNo") = "yes" then
        printfn "Enter mention (with @): "
        mention <- (int) (askInput "int")

    let (tweetJSON:Users_tweet_info) = {
        Type_of_Request = "SendTweet" ;
        Users_ID  = user_currentID ;
        Tweets_ID = "" ;
        Timestamp = (DateTime.Now) ;
        Tweet_mssg_body = content ;
        HashTag_inTweet = hashtag_var ;
        Mention_inTweet = mention ;
        Retweet_count = 0 ;
    }
    Json.serialize tweetJSON

let followerJSON user_currentID = 
    printfn "Whom would you like to follow: "
    let subToUserID = (int) (askInput "int")
    let (subJSON:Secondary_Info) = {
        Type_of_Request = "Subscribe" ;
        Users_ID = user_currentID ;
        Tweet_Owner_ID = subToUserID;
    }
    Json.serialize subJSON

let retweetJSONinfo user_currentID = 
    printfn "Enter tweetId you want to retweet: "
    let retweetID = (askInput "string")
    let (retweetJSON:Retweets_info) = {
        Type_of_Request = "Retweet" ;
        Users_ID  = user_currentID ;
        Matched_TID =  -1 ;
        Tweet_RID = retweetID ;
    }
    Json.serialize retweetJSON

let databaseJSON (option:string) =
    match option with
    | "QueryTag" ->
        printfn "Enter #hashtag you want to query: "
        let hashtag_var = askInput "string"
        let (queryTagJSON:DB_qInfo) = {
            Type_of_Request = "QueryTag" ;
            Users_ID = -1 ;
            HashTag_inTweet = hashtag_var ;
        }
        Json.serialize queryTagJSON
    | "QueryHistory" | "QueryMention" | "QuerySubscribe" ->
        printfn "Please enter the user id for which you want to see results:" 
        let user_id = (int) (askInput "int")
        let (queryJSON:DB_qInfo) = {
            Type_of_Request = option ;
            Users_ID = user_id ;
            HashTag_inTweet = "" ;
        }
        Json.serialize queryJSON
    | _ -> 
        printfn "Wrong input!"
        Environment.Exit 1
        ""

let findtheUserID (jsonStr:string) = 
    let jsonMsg = JsonValue.Parse(jsonStr)
    (jsonMsg?Users_ID.AsInteger())

let register (client: IActorRef) = 
    client <! """{"Type_of_Request":"Register"}"""

let share_tweeet (client: IActorRef) (hashtag: string) (mention: int)= 
    let (request: Users_tweet_info) = {
        Type_of_Request = "SendTweet";
        Users_ID = (int) client.Path.Name;
        Tweets_ID = "";
        Timestamp = DateTime.Now;
        Tweet_mssg_body = "Tweeeeeet";
        HashTag_inTweet = hashtag;
        Mention_inTweet = mention;
        Retweet_count = 0 ;
    }
    client <! (Json.serialize request)

let followUser (client: IActorRef) (ownr: IActorRef) = 
    let (request: Secondary_Info) = {
        Type_of_Request = "Subscribe";
        Users_ID = (int) client.Path.Name;
        Tweet_Owner_ID = (int) ownr.Path.Name;
    }
    client <! (Json.serialize request)

let retweet (client: IActorRef) (targetUserID: int)=
    let (request: Retweets_info) = {
        Type_of_Request = "Retweet";
        Tweet_RID = "";
        Matched_TID = targetUserID;
        Users_ID = (int) client.Path.Name;
    }
    client <! (Json.serialize request)

let login (client: IActorRef) = 
    let (request: Req_connection) = {
        Type_of_Request = "Connect";
        Users_ID = client.Path.Name |> int;
        Sign_Info = "";
    }
    client <! (Json.serialize request)

let logout (client: IActorRef) = 
    let (request: Req_connection) = {
        Type_of_Request = "Disconnect";
        Users_ID = client.Path.Name |> int;
        Sign_Info = ""
    }
    client <! (Json.serialize request)

let showHistory (client: IActorRef) = 
    let (request: DB_qInfo) = {
        Type_of_Request = "QueryHistory";
        Users_ID = client.Path.Name |> int;
        HashTag_inTweet = "";
    }
    client <! (Json.serialize request)

let showMentions (client: IActorRef) (mentionedUserID: int) = 
    let (request: DB_qInfo) = {
        Type_of_Request = "QueryHistory";
        HashTag_inTweet = "";
        Users_ID = mentionedUserID;
    }
    client <! (Json.serialize request)

let showTags (client: IActorRef) (hashtag_var: string)= 
    let (request: DB_qInfo) = {
        Type_of_Request = "QueryTag";
        HashTag_inTweet = hashtag_var;
        Users_ID = 0;
    }
    client <! (Json.serialize request)

let showFollowers (client: IActorRef) (id: int) = 
    let (request: DB_qInfo) = {
            Type_of_Request = "QuerySubscribe";
            HashTag_inTweet = "";
            Users_ID = id;
        }
    client <! (Json.serialize request)

let initializeWSDB webSocket_Server_adrs =
    let wsdbModel = new Dictionary<string, WebSocket>()
    (wsdbModel.Add("Register", new WebSocket(webSocket_Server_adrs      +   "/register")))
    (wsdbModel.Add("SendTweet", new WebSocket(webSocket_Server_adrs     +   "/tweet/send")))
    (wsdbModel.Add("Retweet", new WebSocket(webSocket_Server_adrs       +   "/tweet/retweet")))
    (wsdbModel.Add("Subscribe", new WebSocket(webSocket_Server_adrs     +   "/subscribe")))
    (wsdbModel.Add("Connect", new WebSocket(webSocket_Server_adrs       +   "/login")))
    (wsdbModel.Add("Disconnect", new WebSocket(webSocket_Server_adrs    +   "/logout")))
    (wsdbModel.Add("QueryHistory", new WebSocket(webSocket_Server_adrs  +   "/tweet/query")))
    (wsdbModel.Add("QueryMention", new WebSocket(webSocket_Server_adrs  +   "/mention/query")))
    (wsdbModel.Add("QueryTag", new WebSocket(webSocket_Server_adrs      +   "/hashtag_var/query")))
    (wsdbModel.Add("QuerySubscribe", new WebSocket(webSocket_Server_adrs +  "/subscribe/query")))
    wsdbModel
    
let activateWS (wsforDB:Dictionary<string, WebSocket>) =
    if (not wsforDB.["SendTweet"].IsAlive) then (wsforDB.["SendTweet"].Connect())
    if (not wsforDB.["Retweet"].IsAlive) then (wsforDB.["Retweet"].Connect())
    if (not wsforDB.["Subscribe"].IsAlive) then (wsforDB.["Subscribe"].Connect())
    if (not wsforDB.["Disconnect"].IsAlive) then (wsforDB.["Disconnect"].Connect())
    if (not wsforDB.["QueryHistory"].IsAlive) then (wsforDB.["QueryHistory"].Connect())
    if (not wsforDB.["QueryMention"].IsAlive) then (wsforDB.["QueryMention"].Connect())
    if (not wsforDB.["QueryTag"].IsAlive) then (wsforDB.["QueryTag"].Connect())
    if (not wsforDB.["QuerySubscribe"].IsAlive) then (wsforDB.["QuerySubscribe"].Connect())

let deactivateWS (wsforDB:Dictionary<string, WebSocket>) =
    if (wsforDB.["SendTweet"].IsAlive) then (wsforDB.["SendTweet"].Close())
    if (wsforDB.["Retweet"].IsAlive) then (wsforDB.["Retweet"].Close())
    if (wsforDB.["Subscribe"].IsAlive) then (wsforDB.["Subscribe"].Close())
    if (wsforDB.["Disconnect"].IsAlive) then (wsforDB.["Disconnect"].Close())
    if (wsforDB.["QueryHistory"].IsAlive) then (wsforDB.["QueryHistory"].Close())
    if (wsforDB.["QueryMention"].IsAlive) then (wsforDB.["QueryMention"].Close())
    if (wsforDB.["QueryTag"].IsAlive) then (wsforDB.["QueryTag"].Close())
    if (wsforDB.["QuerySubscribe"].IsAlive) then (wsforDB.["QuerySubscribe"].Close())

let registrationBack (actorNode, wsforDB:Dictionary<string,WebSocket>, flagforTesting:bool) = fun (msg:MessageEventArgs) ->
    let data_reply = (Json.deserialize<Registration_reply_info> msg.Data)
    let successFlag = if (data_reply.Current_Status = "Success") then (true) else (false)

    if successFlag then
        activateWS (wsforDB)
        if flagforTesting then 
            printfn "[%s] Created User %s and logged in" actorNode (data_reply.Description_info.Value)
        else 
        serv_pub_key <- data_reply.Key_server
        if AuthFlag_debug then
            printfn "\n\nServer public key: %A" serv_pub_key
        checkifUserLogin_success <- Success
    else
        if flagforTesting then printfn "[%s] Sign up failed!\n" actorNode
        else checkifUserLogin_success <- Fail
    wsforDB.["Register"].Close()

let loginBack (nodeID, wsforDB:Dictionary<string,WebSocket>, hellman_var: ECDiffieHellman) = fun (msg:MessageEventArgs) ->
    let data_reply = (Json.deserialize<ReqConnect_reply_info> msg.Data)
    match data_reply.Current_Status with
    | "Success" -> 
        activateWS (wsforDB)
        
        wsforDB.["Connect"].Close()
        if AuthFlag_debug then
            printfn "[User%i] Login successful!" nodeID
        let (queryMsg:DB_qInfo) = {
            Type_of_Request = "QueryHistory" ;
            Users_ID = (data_reply.Description_info.Value|> int) ;
            HashTag_inTweet = "" ;
        }
        wsforDB.["QueryHistory"].Send(Json.serialize queryMsg)
        checkifUserLogin_success <- Success
    | "Auth" -> 
        let challenge = data_reply.Auth_header |> Convert.FromBase64String
        if AuthFlag_debug then
            printfn "Challenge from Server: %A" data_reply.Auth_header
        let signature = authSignFetch challenge hellman_var
        if AuthFlag_debug then 
            printfn "Final signature after user's key : %A" signature
        let (authMsg:Req_connection) = {
            Users_ID = data_reply.Description_info.Value|> int;
            Type_of_Request = "Auth";
            Sign_Info = signature;
        }
        wsforDB.["Connect"].Send(Json.serialize authMsg)
    | _ ->
        checkifUserLogin_success <- Fail
        print_OnConsole (sprintf "Login failed for user: %i\nError mssg: %A" nodeID (data_reply.Description_info.Value))
        wsforDB.["Connect"].Close()

let disconnectCallback (actorNode, wsforDB:Dictionary<string,WebSocket>) = fun (msg:MessageEventArgs) ->
    deactivateWS (wsforDB)
    checkifUserLogin_success <- Success

let replyBack (actorNode) = fun (msg:MessageEventArgs) ->
    let data_reply = (Json.deserialize<Tweet_reply_info> msg.Data)
    let successFlag = if (data_reply.Current_Status = "Success") then (true) else (false)
    if successFlag then
        checkifUserLogin_success <- Success
        print_OnConsole (sprintf "[%s] %s" actorNode (data_reply.Description_info.Value))
    else 
        checkifUserLogin_success <- Fail
        print_OnConsole (sprintf "[%s] Error!\n%s" actorNode (data_reply.Description_info.Value))

let showTweet message = 
    let replyontweet_data = (Json.deserialize<Reply_on_Tweet> message)
    let tweet_data = replyontweet_data.Users_tweet_info
    printfn "\n~~~~~~~~~~~~~~~~~~~~~~~~"
    printfn "Index: %i      Timestamp: %s" (replyontweet_data.Current_Status) (tweet_data.Timestamp.ToString())
    printfn "Author: User%i" (tweet_data.Users_ID)
    let mentionStr = if (tweet_data.Mention_inTweet < 0) then "@N/A" else ("@User"+tweet_data.Mention_inTweet.ToString())
    let tagStr = if (tweet_data.HashTag_inTweet = "") then "#N/A" else (tweet_data.HashTag_inTweet)
    printfn "Tweet_mssg_body: {%s}\n%s  %s  Retweet times: %i" (tweet_data.Tweet_mssg_body) (tagStr) (mentionStr) (tweet_data.Retweet_count)
    printfn "TID: %s" (tweet_data.Tweets_ID)

let showFllwrs message actorNode =
    let subReplyInfo = (Json.deserialize<Secondary_Reply> message)
    printfn "\n~~~~~~~~~~~~~~~~~~~~~~~~~"
    printfn "Name: %s" ("User" + (subReplyInfo.Matched_TID.ToString()))
    printf "Followed By: "
    for id in subReplyInfo.Follower do
        printf "\nUser%i " id
    printfn "\n"
    print_OnConsole (sprintf "[%s] Showing User%i's followers info" actorNode subReplyInfo.Matched_TID)

let databaseBack (actorNode) = fun (msg:MessageEventArgs) ->
    let  jsonMsg = JsonValue.Parse(msg.Data)
    let  reqType = jsonMsg?Type.AsString()
    if reqType = "ShowTweet" then
        showTweet (msg.Data)
    else if reqType = "ShowSub" then 
        showFllwrs (msg.Data) (actorNode)
    else
        let successFlag = if (jsonMsg?Current_Status.AsString() = "Success") then (true) else (false)
        if successFlag then 
            checkifUserLogin_success <- Success
            print_OnConsole (sprintf "[%s]\n%s" actorNode (jsonMsg?Description_info.AsString()))
        else 
            checkifUserLogin_success <- Fail
            print_OnConsole (sprintf "[%s]\n%s" actorNode (jsonMsg?Description_info.AsString()))


let askLogintoServer (msg:string, flagforTesting, wsLogin:WebSocket, nodeID, publicKey) =
    wsLogin.Connect()
    if flagforTesting then
        let regMsg:Registration_JSON = { 
            Type_of_Request = "Register" ; 
            Users_ID = nodeID ; 
            Primary_username = "User"+ (nodeID.ToString()) ; 
            publicKey = publicKey ;
        }
        let data = (Json.serialize regMsg)
        wsLogin.Send(data)
    else
        let message = Json.deserialize<Registration_JSON> msg
        let regMsg:Registration_JSON = { 
            Type_of_Request = message.Type_of_Request; 
            Users_ID = message.Users_ID; 
            Primary_username = message.Primary_username ; 
            publicKey = publicKey ;
        }
        let data = (Json.serialize regMsg)
        wsLogin.Send(data)
   
let datatoServer (msg:string, reqType, wsforDB:Dictionary<string,WebSocket>, actorNode) =
    if not (wsforDB.[reqType].IsAlive) then
        if reqType = "Disconnect" then
            wsforDB.[reqType].Connect()
            wsforDB.[reqType].Send(msg)
            print_OnConsole (sprintf "[%s]\nServer disconnected" actorNode)
            checkifUserLogin_success <- SessionTimeout
        else
            checkifUserLogin_success <- SessionTimeout
    else 
        wsforDB.[reqType].Send(msg)

let tweetHandleer (msg:string, ws:WebSocket, actorNode, hellman_var: ECDiffieHellman) =
    if not (ws.IsAlive) then
        checkifUserLogin_success <- SessionTimeout        
    else 
        let key = findSecretkey_shared hellman_var serv_pub_key

        let signature = signHMAC msg key
        if AuthFlag_debug then
            printfn "~~Using user's private key and server's public key to generate a shared secret key~~"
            printfn "Secret key:\n %A" (key|>Convert.ToBase64String)
            printfn "Message: %A" msg
            printfn "~~Using HMAC to sign the key~~"
            printfn "HMAC sign: %A" signature
        let (signedMsg:Tweet_marked) = {
            JSON_unmakred = msg
            H_Sign = signature
        }
        let data = (Json.serialize signedMsg)
        ws.Send(data)

let displayConsoleOptions option user_currentID= 
    match option with
    | "loginFirst" ->
        printfn "Welcome to twitter! What would you like to do\n"
        printfn "Press 1 to sign up"
        printfn "Press 2 to login"
        printfn "Press 3 to quit"
        printf ">"
    | "afterLogin" ->
        printfn "\nWelcome User%i ! What would you like to do\n" user_currentID
        printfn "Press 1 to tweet"
        printfn "Press 2 to retweet"
        printfn "Press 3 to follow an user"
        printfn "Press 4 to logout"
        printfn "Press 5 to see your tweets"
        printfn "Press 6 to see hashtags"
        printfn "Press 7 to see mentions"
        printfn "Press 8 to see your followers"
        printfn "Press 9 to quit"
        printf ">"
    | _ ->
        ()

let setTimeout _ =
    checkifUserLogin_success <- Timeout

let haltTimeforServer (timeout:float) =
    let timer = new Timers.Timer(timeout*1000.0)
    checkifUserLogin_success <- Waiting
    timer.Elapsed.Add(setTimeout)
    timer.Start()
    print_OnConsole "Waiting for server to reply"
    while checkifUserLogin_success = Waiting do ()
    timer.Close()

let haltTimewithSelfLogin (timeout:float, command:string) =
    haltTimeforServer timeout
    if checkifUserLogin_success = SessionTimeout then
        print_OnConsole (sprintf "Session timeout")

let intializeUI terminalRef =    

    let mutable user_currentID = -1
    let mutable curState= 0
    while true do
        while curState = 0 do
            (displayConsoleOptions "loginFirst" user_currentID)
            let inputStr = Console.ReadLine()
            match inputStr with
                | "1" | "register" ->
                    let requestJSON = regJSON_output "key"
                    let tmpuserID = findtheUserID requestJSON
                    terminalRef <! requestJSON
  
                    haltTimeforServer (5.0)
                    if checkifUserLogin_success = Success then
                        print_OnConsole ("Signed up successfully and logged in as User"+ tmpuserID.ToString())
                        terminalRef <! """{"Type_of_Request":"UserModeOn", "CurUserID":"""+"\""+ tmpuserID.ToString() + "\"}"
                        user_currentID <- tmpuserID
                        curState <- 1
                        (displayConsoleOptions "afterLogin" user_currentID)
                    else if checkifUserLogin_success = Fail then
                        print_OnConsole (sprintf "Faild to sign up for Users_ID: %i\nSeems like this user already exists!" tmpuserID)

                    else
                        print_OnConsole ("Failed to sign uo for Users_ID: " + tmpuserID.ToString() + "\n(No response from server)")


                | "2" | "login" ->
                    let requestJSON = reqCnDjson ("Connect", -1)
                    let tmpuserID = findtheUserID requestJSON
                    terminalRef <! requestJSON

                    haltTimeforServer (5.0)
                    if checkifUserLogin_success = Success then
                        print_OnConsole ("Successfully connected and login as User"+ tmpuserID.ToString())
                        terminalRef <! """{"Type_of_Request":"UserModeOn", "CurUserID":"""+"\""+ tmpuserID.ToString() + "\"}"
                        user_currentID <- tmpuserID
                        curState <- 1
                        (displayConsoleOptions "afterLogin" user_currentID)
                    else if checkifUserLogin_success = Fail then
                        ()
                    else
                        print_OnConsole ("Faild to login and login for Users_ID: " + tmpuserID.ToString() + "\n(Server no response, timeout occurs)")


                | "3" | "exit" | "ex" ->
                    print_OnConsole "Exited from console"
                    Environment.Exit 1
                | _ ->
                    ()


        while curState = 1 do
            let inputStr = Console.ReadLine()
            match inputStr with
                | "1" ->
                    terminalRef <! Tweet_infoJSON user_currentID
                    haltTimewithSelfLogin (5.0, "sendtweet")

                | "2" -> 
                    terminalRef <! retweetJSONinfo user_currentID
                    haltTimewithSelfLogin (5.0, "retweet")

                | "3"-> 
                    terminalRef <! followerJSON user_currentID
                    haltTimewithSelfLogin (5.0, "subscribe")

                | "4" ->
                    terminalRef <! reqCnDjson ("Disconnect", user_currentID)
                    haltTimeforServer (5.0)
                    if checkifUserLogin_success = Success then
                        print_OnConsole ("Successfully logged out User"+ user_currentID.ToString())
                        user_currentID <- -1
                        curState <- 0
                    else if checkifUserLogin_success = SessionTimeout then
                        user_currentID <- -1
                        curState <- 0

                | "5"-> 
                    terminalRef <! databaseJSON "QueryHistory"
                    haltTimewithSelfLogin (10.0, "QueryHistory")

                | "6" -> 
                    terminalRef <! databaseJSON "QueryTag"
                    haltTimewithSelfLogin (5.0, "QueryTag")

                | "7"-> 
                    terminalRef <! databaseJSON "QueryMention"
                    haltTimewithSelfLogin (5.0, "QueryMention")

                | "8"-> 
                    terminalRef <! databaseJSON "QuerySubscribe"
                    haltTimewithSelfLogin (5.0, "QuerySubscribe")

                | "9" ->
                    terminalRef <! reqCnDjson ("Disconnect", user_currentID)
                    haltTimeforServer (5.0)
                    print_OnConsole "Exited the console!"
                    Environment.Exit 1
                | _ ->
                    (displayConsoleOptions "afterLogin" user_currentID)
                    ()


let userBossActor (flagforTesting) (clientMailbox:Actor<string>) =
    let mutable actorNode = "User" + clientMailbox.Self.Path.Name
    let mutable nodeID = 
        match (Int32.TryParse(clientMailbox.Self.Path.Name)) with
        | (true, value) -> value
        | (false, _) -> 0
    let nodeECDH = ECDiffieHellman.Create()
    let nodePublicKey = nodeECDH.ExportSubjectPublicKeyInfo() |> Convert.ToBase64String

    let wsforDB = initializeWSDB (webSocket_Server_adrs)
    (wsforDB.["Register"]).OnMessage.Add(registrationBack (actorNode, wsforDB, flagforTesting))
    (wsforDB.["SendTweet"]).OnMessage.Add(replyBack (actorNode))
    (wsforDB.["Retweet"]).OnMessage.Add(replyBack (actorNode))
    (wsforDB.["Subscribe"]).OnMessage.Add(replyBack (actorNode))
    (wsforDB.["QueryHistory"]).OnMessage.Add(databaseBack (actorNode))
    (wsforDB.["QueryMention"]).OnMessage.Add(databaseBack (actorNode))
    (wsforDB.["QueryTag"]).OnMessage.Add(databaseBack (actorNode))
    (wsforDB.["QuerySubscribe"]).OnMessage.Add(databaseBack (actorNode))
    (wsforDB.["Disconnect"]).OnMessage.Add(disconnectCallback (actorNode, wsforDB))
    (wsforDB.["Connect"]).OnMessage.Add(loginBack (nodeID, wsforDB, nodeECDH))

    let rec loop() = actor {
        let! (message: string) = clientMailbox.Receive()
        let  jsonMsg = JsonValue.Parse(message)
        let  reqType = jsonMsg?Type_of_Request.AsString()
        match reqType with
            | "Register" ->                
                askLogintoServer (message,flagforTesting, wsforDB.[reqType], nodeID, nodePublicKey)
            | "SendTweet" ->
                tweetHandleer (message, wsforDB.["SendTweet"], actorNode, nodeECDH)
            | "Retweet" | "Subscribe"
            | "QueryHistory" | "QueryMention" | "QueryTag" | "QuerySubscribe" 
            | "Disconnect" ->
                datatoServer (message, reqType, wsforDB, actorNode)        
            | "Connect" ->
                let wssCon = wsforDB.["Connect"]
                wssCon.Connect()
                wssCon.Send(message)

            | "UserModeOn" ->
                let user_currentID = jsonMsg?CurUserID.AsInteger()
                nodeID <- user_currentID
                actorNode <- "User" + user_currentID.ToString()

            | _ ->
                printfn "Node \"%s\" unexpected msg: \"%s\"" actorNode reqType
                Environment.Exit 1
         
        return! loop()
    }
    loop()

[<EntryPoint>]
let main argv =
    try
        universal_timer.Start()
        let programMode = argv.[0]

        if programMode = "user" then
            
            let terminalRef = spawn system "-Terminal" (userBossActor false)
            intializeUI terminalRef

        else if programMode = "tester" then
            printfn "\n\nEnabled authentication messages\n"
            AuthFlag_debug <- true
            let terminalRef = spawn system "-Terminal" (userBossActor false)
            intializeUI terminalRef
        else
            printfn "\n\nWrong argument entered! Enter 'dotnet run user' or 'dotnet run tester'\n"
            Environment.Exit 1

    with | :? IndexOutOfRangeException ->
            printfn "\n\nWrong argument entered! Enter 'dotnet run user'  or 'dotnet run tester'\n\n"

         | :? FormatException ->
            printfn "\nException occured in format\n"

    0 