

function role(type){
    
    return function (req,res,next){
        if(req.session.accoountType===type){
            next()
        }else{
            return res.status(403).render("errors/403");
        }
    }
}

module.exports=role;