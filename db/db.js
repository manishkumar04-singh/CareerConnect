const mongodb=require("mongodb");

const mongoclient=mongodb.MongoClient;

let database;

async function connectdatabase(){
    const client=await mongoclient.connect('mongodb://127.0.0.1:27017');
    database=client.db("careeerconnect");
}

function getdb(){
    if(!database){
        throw {message:"Database connection not established"};
    }
    return database;
}

module.exports={
    connectTOdatabase:connectdatabase,
    getdb:getdb
}