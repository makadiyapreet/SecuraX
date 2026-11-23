function getDbConfig() {
    const password = process.env.DB_PASSWORD || "";
    return { host: "localhost", user: "admin", password };
}
