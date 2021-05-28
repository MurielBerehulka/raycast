use std::convert::Infallible;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use hyper::{Body, Request, Response, Server, Method};
use hyper::service::{make_service_fn, service_fn};
use mongodb::{bson::{doc, Bson, Document, from_bson, oid::ObjectId}, sync::{Client, Collection}};
use bcrypt::{hash, verify};
use files_buffer::FilesBuferr;
use json::JsonValue;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use serde_json;
use chrono::Utc;

//next internal server error: 50036

const TOKEN_SIZE: usize = 32;

const HASH_COST: u32 = 10;

const PUBLIC_DIR: &str = "public";
const ERROR_FILE: &str = "/error404.html";

async fn handle_get (req: Request<Body>,files: &FilesBuferr)-> Result<Response<Body>, Infallible> {
    let mut path = req.uri().path();
    path = match path {
        "/" => "/index.html",
        "/analytics" => "/analytics.html",
        _ => path
    };
    match files.buffer.get(path) {
        Some(file) => return Ok(Response::new(Body::from(file.to_string()))),
        None => match files.buffer.get(ERROR_FILE) {
            Some(file) => return Ok(Response::new(Body::from(file.to_string()))),
            None => return Ok(Response::new(Body::from("Error 5003\r\nFile not found")))
        }
    }
}

async fn handle_post (
        req: Request<Body>,
        users_collection: Collection,
        streams_collection: Collection,
        users: Arc<Mutex<HashMap<ObjectId, User>>>,
        userid_by_token: Arc<Mutex<HashMap<String, ObjectId>>>,
        token_pass_by_email: Arc<Mutex<HashMap<String, (String, String)>>>,
        hosts: Arc<Mutex<HashMap<String, ObjectId>>>
    ) -> Result<Response<Body>, Infallible> {
        match req.uri().path() {
            "/users/login" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let email = match body["email"].as_str() {
                    Some(v) => v,
                    None => return res("Email is required", 400)
                };
                let password = match body["password"].as_str() {
                    Some(v) => v,
                    None => return res("Password is required", 400)
                };
                let token_passes = token_pass_by_email.lock().unwrap();
                match token_passes.get(&email.to_string()) {
                    Some (token_pass) => {
                        match verify(password.to_string(), &token_pass.1) {
                            Ok(ismatch) => {
                                if ismatch {
                                    return res(token_pass.0.to_string(), 200)
                                }else{
                                    return res("Invalid E-mail or password", 400)
                                }
                            },
                            Err (_) => return res("Error 5006", 500)
                        }
                    },
                    None => {
                        drop(token_passes);
                        let user = match users_collection.find_one(doc!{ "email" : email }, None) {
                            Ok (user) => {
                                match user {
                                    Some (user) => user,
                                    None => return res("Invalid E-mail or password", 400)
                                }
                            },
                            Err (_) => return res("Error 5004", 500)
                        };
                        let hashed = match user.get("password").and_then(Bson::as_str) {
                            Some (v) => v,
                            None => return res("Error 50011", 500)
                        };
                        let logged = match verify(password, hashed) {
                            Ok (v) => v,
                            Err (_) => return res("Error 5009", 500)
                        };
                        if logged {
                            let userid = match user.get("_id").and_then(Bson::as_object_id) {
                                Some (v) => v,
                                None => return res("Error 50015", 500)
                            };
                            let mut userid_by_token = userid_by_token.lock().unwrap();
                            let token = generate_token(&userid_by_token);
                            userid_by_token.insert(token.to_string(), userid.clone());
                            drop(userid_by_token);
                            users.lock().unwrap().insert(userid.clone(), User {
                                id: userid.clone(),
                                email: email.to_string(),
                                username: user.get("username").and_then(Bson::as_str).unwrap().to_string(),
                                pass_hashed: hashed.to_string(),
                                games: get_games_from_user(&user),
                                host: false,
                                host_sub_server: 0
                            });
                            token_pass_by_email.lock().unwrap().insert(email.to_string(), (token.clone(), hashed.to_string()));
                            return res(token, 200)
                        } else {
                            return res("Invalid E-mail or password", 400)
                        }
                    }
                }
            }
            "/users/register" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let email = match body["email"].as_str() {
                    Some(email) => {
                        if is_email_valid(email) {
                            email
                        } else {
                            return res("E-mail not valid", 400)
                        }
                    },
                    None => return res("Email is required", 400)
                };
                match users_collection.find_one(doc!{ "email" : email }, None) {
                    Ok (user) => {
                        if let Some(_) = user {
                            return res("E-mail is already in use", 400)
                        }
                    },
                    Err (_) => return res("Error 5005", 500)
                }
                let password = match body["password"].as_str() {
                    Some(v) => {
                        if v.len() < 5 {
                            return res("Password is too short", 400)
                        } else {
                            v
                        }
                    },
                    None => return res("Password is required", 400)
                };
                let username = match body["username"].as_str() {
                    Some(v) => {
                        if v.len() < 5 {
                            return res("Username is too short", 400)
                        } else {
                            v
                        }
                    },
                    None => return res("Username is required", 400)
                };
                let password_hashed = match hash(&password, HASH_COST) {
                    Ok (v) => v,
                    Err (_) => return res("Error 5001", 500)
                };
                match users_collection.insert_one(doc! {
                    "email": &email,
                    "username": &username,
                    "password": &password_hashed,
                    "games": []
                }, None) {
                    Ok (_) => return res("Ok", 200),
                    Err (_) => return res("Error 5002", 500)
                }
            }
            "/users/me" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let token = match body["token"].as_str() {
                    Some(v) => v,
                    None => return res("Token is required", 400)
                };
                let userid_by_token = userid_by_token.lock().unwrap();
                let users = users.lock().unwrap();
                let user = match userid_by_token.get(token) {
                    Some(userid) => {
                        match users.get(userid) {
                            Some (v) => v,
                            None => return res("Error 50017", 500)
                        }
                    },
                    None => return res("Invalid token", 400)
                };
                drop(userid_by_token);
                let games_json = serde_json::to_string(&user.games).unwrap_or_default();
                return res(format!(
                    "{{\"email\":\"{}\",\"username\":\"{}\",\"games\":{}}}",
                    user.email, user.username, games_json
                ), 200)
            }
            "/users/host/games/add" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let token = match body["token"].as_str() {
                    Some(v) => v,
                    None => return res("Token is required", 400)
                };
                let name = match body["name"].as_str() {
                    Some(v) => v,
                    None => return res("Name is required", 400)
                };
                let path = match body["path"].as_str() {
                    Some(v) => v,
                    None => return res("Path is required", 400)
                };
                let icon = match body["icon"].as_str() {
                    Some(v) => v,
                    None => ""
                };
                let userid_by_token = userid_by_token.lock().unwrap();
                let mut users = users.lock().unwrap();
                let user = match userid_by_token.get(token) {
                    Some(userid) => {
                        match users.get_mut(userid) {
                            Some (v) => v,
                            None => return res("Error 50021", 500)
                        }
                    },
                    None => return res("Invalid token", 400)
                };
                drop(userid_by_token);
                for game in &user.games {
                    if game.name == name {
                        return res("Game with the same name already exist", 400)
                    }
                }
                user.games.push(Game {
                    name: name.to_string(),
                    path: path.to_string(),
                    icon: icon.to_string()
                });
                match users_collection.update_one(
                    doc!{ "_id" : &user.id }, 
                    doc!{ "$push" : { "games": {
                        "name": name,
                        "path": path,
                        "icon": icon
                    } } }, 
                    None
                ){
                    Ok (update_res) => {
                        if update_res.modified_count > 0 {
                            return res("Ok", 200)
                        } else {
                            if update_res.matched_count < 0{
                                return res("Error 50013", 500)
                            } else {
                                return res("Error 50026", 500)
                            }
                        }
                    },
                    Err (_) => return res("Error 50023", 500)
                }
            }
            "/users/host/games/remove" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let token = match body["token"].as_str() {
                    Some(v) => v,
                    None => return res("Token is required", 400)
                };
                let name = match body["name"].as_str() {
                    Some(v) => v,
                    None => return res("Name is required", 400)
                };
                let mut i: usize = 0;
                let userid_by_token = userid_by_token.lock().unwrap();
                let mut users = users.lock().unwrap();
                let user = match userid_by_token.get(token) {
                    Some(userid) => {
                        match users.get_mut(userid) {
                            Some (v) => v,
                            None => return res("Error 50018", 500)
                        }
                    },
                    None => return res("Invalid token", 400)
                };
                drop(userid_by_token);
                match user.games.len() {
                    0usize => return res("Ok", 200),
                    1usize => {
                        user.games.clear();
                        match users_collection.update_one(
                            doc!{ "_id" : &user.id }, 
                            doc!{ "$set" : { "games": [] } },
                            None
                        ) {
                            Ok (update_res) => {
                                if update_res.modified_count > 0 {
                                    return res("Ok", 200)
                                } else {
                                    return res("Error 5008", 500)
                                }
                            },
                            Err (_) => return res("Error 5007", 500)
                        }
                    },
                    _ => {
                        for game in user.games.iter() {
                            if game.name == name {
                                break;
                            }
                            i = i + 1;
                        }
                        user.games.remove(i);
                        match users_collection.update_one(
                            doc!{ "_id" : &user.id }, 
                            doc!{ "$pull" : { "games": { "name" : name } } },
                            None
                        ) {
                            Ok (update_res) => {
                                if update_res.modified_count > 0 {
                                    return res("Ok", 200)
                                } else {
                                    return res("Error 50012", 500)
                                }
                            },
                            Err (_) => return res("Error 50025", 500)
                        }
                    }
                }
            }
            "/users/host/start" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let token = match body["token"].as_str() {
                    Some(v) => v,
                    None => return res("Token is required", 400)
                };
                let host_sub_server = match body["host_sub_server"].as_u16() {
                    Some(v) => v,
                    None => return res("host_sub_server is required", 400)
                };
                match userid_by_token.lock().unwrap().get(token) {
                    Some (userid) => {
                        match users.lock().unwrap().get_mut(userid) {
                            Some (user) => {
                                user.host_sub_server = host_sub_server;
                                hosts.lock().unwrap().insert(token.to_string(), userid.clone());
                                return res("Ok", 200);
                            },
                            None => return res("Error 50019", 500)
                        }
                    },
                    None => return res("Invalid token", 400)
                }
            }
            "/users/host/stop" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let token = match body["token"].as_str() {
                    Some(v) => v,
                    None => return res("Token is required", 400)
                };
                hosts.lock().unwrap().remove(token);
                return res("Ok", 200)
            }
            "/users/host/list" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let start = match body["start"].as_u16() {
                    Some(v) => v,
                    None => return res("Start is required", 400)
                };
                let mut i: u16 = start;
                let mut response: String = String::from('[');
                let mut end = match body["end"].as_u16() {
                    Some(v) => v,
                    None => return res("End is required", 400)
                };
                end = end - 1;
                let hosts = hosts.lock().unwrap();
                let hosts_len = hosts.len() as u16;
                if end - start > 20 {
                    end = start + 20;
                }
                if end > hosts_len{
                    end = hosts_len;
                }
                let users = users.lock().unwrap();
                for host in hosts.iter() {
                    if i >= end {
                        break;
                    }
                    let user = users.get(host.1).unwrap();
                    let games_json = match serde_json::to_string(&user.games) {
                        Ok (v) => v,
                        Err (_) => return res("Error 50016", 500)
                    };
                    response = format!(
                        "{}{{\
                            \"id\":\"{}\",\
                            \"username\":\"{}\",\
                            \"host_sub_server\":{},\
                            \"games\":{}\
                        }}",
                        response,
                        user.id,
                        user.username,
                        user.host_sub_server,
                        games_json
                    );
                    if i < end - 1 {
                        response.push(',');
                    }
                    i = i + 1;
                }
                drop(users);
                drop(hosts);
                response.push(']');
                return res(response, 200)
            }
            "/users/host/req" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let token = match body["token"].as_str() {
                    Some(v) => v,
                    None => return res("Token is required", 400)
                };
                let machine_id = match body["machine_id"].as_str() {
                    Some(v) => match ObjectId::with_string(v) {
                        Ok(v) => v,
                        Err(_) => return res("Machine id is invalid", 400)
                    },
                    None => return res("Machine id is required", 400)
                };
                let game_name = match body["game_name"].as_str() {
                    Some(v) => v,
                    None => return res("Game name is required", 400)
                };
                let users = users.lock().unwrap();
                let game_path: String = match users.get(&machine_id) { 
                    Some (machine) => {
                        match machine.games.iter().find(|&x| x.name == game_name) {
                            Some (v) => v.path.clone(),
                            None => return res("Game name is invalid", 400)
                        }
                    },
                    None => return res("Machine id is invalid", 400)
                };
                drop(users);
                let userid = match userid_by_token.lock().unwrap().get(token) {
                    Some(v) => v.clone(),
                    None => return res("User id is invalid", 400)
                };
                match streams_collection.find_one(doc!{
                    "_id" : &userid
                }, None) {
                    Ok (found) => {
                        if let Some(_) = found {
                            return res("Already in stream", 400)
                        }
                    },
                    Err (_) => return res("Error 50034", 400)
                }
                match streams_collection.insert_one(doc!{
                    "_id" : userid,
                    "host_id" : machine_id,
                    "game_name" : game_name,
                    "path": game_path,
                    "started_at": Utc::now(),
                    "resolution": "640x480"
                }, None) {
                    Ok (_) => return res("Ok", 200),
                    Err (_) => return res("Error 50033", 500)
                }
            },
            "/users/host/req/stop" => {
                let body = match get_body(req).await {
                    Some(v) => v,
                    None => return res("Invalid body", 400)
                };
                let token = match body["token"].as_str() {
                    Some(v) => v,
                    None => return res("Token is required", 400)
                };
                let userid = match userid_by_token.lock().unwrap().get(token) {
                    Some(v) => v.clone(),
                    None => return res("User id is invalid", 400)
                };
                if let Err(_) = streams_collection.delete_one(doc!{
                    "_id" : userid
                }, None) {
                    return res("Error 50035", 400)
                };
                return res("Ok", 200)
            }
            _ => res("Path not found", 404)
        }
}

#[tokio::main]
async fn main() {
    println!("Connecting to mongodb ...");

    let client = match Client::with_uri_str("mongodb+srv://user:JmkqeB7umZy9ic3h@cluster0.z2y7d.mongodb.net/") {
        Ok(result) => {
            result
        },
        Err(err) => {
            panic!("{}",err);
        }
    };
    let db = client.database("usersdb");
    let users_collection = db.collection("users");
    let streams_collection = db.collection("streams");

    println!("Buffering public files ...");
    let files = Arc::new(FilesBuferr::new(PUBLIC_DIR));

    let users: Arc<Mutex<HashMap<ObjectId, User>>> = Arc::new(Mutex::new(HashMap::new()));
    let userid_by_token: Arc<Mutex<HashMap<String, ObjectId>>> = Arc::new(Mutex::new(HashMap::new()));
    let tokenpass_by_email: Arc<Mutex<HashMap<String, (String, String)>>> = Arc::new(Mutex::new(HashMap::new()));
    let hosts: Arc<Mutex<HashMap<String, ObjectId>>> = Arc::new(Mutex::new(HashMap::new()));
    
    println!("Starting server ...");
    let make_svc = make_service_fn(move |_| {
        let users_collection = users_collection.clone();
        let streams_collection = streams_collection.clone();
        let users = users.clone();
        let userid_by_token = userid_by_token.clone();
        let tokenpass_by_email = tokenpass_by_email.clone();
        let hosts = hosts.clone();
        let files = files.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let users_collection = users_collection.clone();
                let streams_collection = streams_collection.clone();
                let users = users.clone();
                let userid_by_token = userid_by_token.clone();
                let tokenpass_by_email = tokenpass_by_email.clone();
                let hosts = hosts.clone();
                let files = files.clone();
                async move {
                    match req.method() {
                        &Method::GET => handle_get(req, files.as_ref()).await,
                        &Method::POST => {
                            handle_post(
                                req,
                                users_collection,
                                streams_collection,
                                users,
                                userid_by_token,
                                tokenpass_by_email,
                                hosts
                            ).await
                        },
                        _ => res("Invalid method", 404)
                    }
                }
            }))
        }
    });

    let addr = ([127, 0, 0, 1], 7878).into();

    let server = Server::bind(&addr).serve(make_svc);
    println!("Server running.");
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

#[derive(Serialize, Deserialize)]
pub struct Game {
    pub name: String,
    pub path: String,
    pub icon: String
}

struct User {
    pub id: ObjectId,
    pub email: String,
    pub username: String,
    pub pass_hashed: String,
    pub games: Vec<Game>,
    pub host: bool,
    pub host_sub_server: u16
}

fn is_email_valid (email: &str) -> bool {
    let mut atsign: bool = false;
    for c in email.chars() {
        match c {
            '{' | '}' | '=' | ':' | ',' | ';' | '"' | '\'' | '\\' | '/' => return false,
            '@' => {
                if atsign {return false}
                atsign = true
            },
            _ => {}
        }
    }
    return atsign
}

async fn get_body (req: Request<Body>) -> Option<JsonValue> {
    match hyper::body::to_bytes(req.into_body()).await {
        Ok (_body) => {
            let b = String::from_utf8_lossy(&_body);
            match json::parse(&b) {
                Ok (body) => return Some(body),
                Err (_) => return None
            }
        },
        Err (_) => return None
    }
}

fn get_token () -> String {
    format!("{:?}", thread_rng().sample_iter(&Alphanumeric).take(TOKEN_SIZE).collect::<Vec<u8>>())
}
fn generate_token (users: &HashMap<String, ObjectId>) -> String {
    let mut token: String = get_token();
    while users.contains_key(&token) {
        token = get_token();
    }
    token
}

fn get_games_from_user (user: &Document) -> Vec<Game> {
    let mut games: Vec<Game> = Vec::new();
    match user.get("games").and_then(Bson::as_array) {
        Some (games_doc) => {
            for game_bson in games_doc {
                let game: Game = from_bson(game_bson.clone()).unwrap();
                games.push(game)
            }
        }, None => {}
    }
    games
}

fn res<S: AsRef<str>>(data: S, status: u16) -> std::result::Result<hyper::Response<hyper::Body>, std::convert::Infallible>{
    Ok(Response::builder().status(status).body(hyper::Body::from(data.as_ref().to_string())).unwrap())
}
