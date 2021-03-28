use configparser::ini::Ini;

pub fn readconfig() -> (String, String, String) {
    let mut config = Ini::new();
    let _map = config.load("config.ini");

    let updatecycle = config.get("radar", "updatecycle").unwrap();
    let server_ip = config.get("server", "ip").unwrap();
    let server_port = config.get("server", "port").unwrap();

    return (updatecycle, server_ip, server_port);
}
