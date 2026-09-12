const mongodb=require("mongodb");

const mongoclient=mongodb.MongoClient;

let database;

async function connectdatabase(){
    const client=await mongoclient.connect(process.env.MONGODB_URI);
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