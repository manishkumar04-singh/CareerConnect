require("dotenv").config();

const express = require("express");
const path = require("path");

const app = express();
const db=require('./db/db.js');
const bcrypt=require("bcrypt");
const session=require("express-session");
const mongodbConnect=require("connect-mongodb-session")(session);

const {ObjectId}=require("mongodb");
const checkObjectId=require("./middleware/validateObjectId.js")
const multer=require("multer");

const nodemailer=require("nodemailer");


const Auth=require('./middleware/auth.js');
const role=require('./middleware/role.js');
const { arrayBuffer } = require("stream/consumers");
const { create } = require("domain");
const { relative } = require("path/win32");
const { title } = require("process");
const { register } = require("module");

const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const resumeStorage = new CloudinaryStorage({
    cloudinary: cloudinary,

    params: {
        folder: "careerconnect/resumes",

        resource_type: "raw",

        public_id: (req, file) => {
            return Date.now() + "-" + file.originalname;
        }
    }
});
const PORT =  process.env.PORT || 3000;;

const storeSession=new mongodbConnect({
    uri:process.env.MONGODB_URI,
    databaseName:'careeerconnect',
    collection:'sessions'
})
// EJS
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));


// Static files
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({extended:true}));

app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:false,
    store:storeSession,

    cookie:{
        httpOnly:true,
        secure:false,
        sameSite:"lax"
    }
}));

console.log("USER:", process.env.EMAIL_USER);
console.log("PASS length:", process.env.EMAIL_PASS?.length);
const transporter=nodemailer.createTransport({
    service: "gmail",
    auth: {
        user:process.env.EMAIL_USER,
        pass:process.env.EMAIL_PASS,
    }

})

// Home page
app.get("/", (req, res) => {
    res.render("index");
});
app.get("/login",(req, res) => {
    res.render("auth/login");
});

app.get("/register",(req,res)=>{
    res.render("auth/register");
});

app.post("/register",async (req,res)=>{
    const data = req.body;
    const existingUser = await db.getdb().collection("users").findOne({
        email: data.email
    });

    if (existingUser) {
        return res.render("auth/register",{emailDuplicate:true,Msg:"Email is already registered."});
    }

    if (data.password !== data.confirmPassword) {
        return res.render("auth/register",{emailDuplicate:true,Msg:"Both Password Doesn't Match."});
    }

    if (
        !data.name ||
        !data.email ||
        !data.password ||
        !data.confirmPassword ||
        !data.accountType
    ) {
        return res.send("Please fill all required fields");
    }
    if (data.accountType !== "student" && data.accountType !== "recruiter") {
        return res.status(404).render("errors/404.ejs");
    }
    const hashedPassword = await bcrypt.hash(data.password, 10);
    const user = {
        name: data.name,
        email: data.email,
        password: hashedPassword,
        accountType: data.accountType,
        terms: data.terms,
    }
    
    await db.getdb().collection("users").insertOne(user);
    

    res.redirect("/login");
})
app.post("/login",async (req,res)=>{
    const data=req.body;
    const user=await db.getdb().collection("users").findOne({email:data.email});
    if(!user){
        
        return res.render("auth/login",{registered:false,Msg:`
            This email is not registered.
              Create an account first.
            `  
        });
    }
    const ispasswordValid=await bcrypt.compare(data.password,user.password);
    if(!ispasswordValid){
        return res.render("auth/login", {
            registered: false, Msg: `
            Entered Password is incorrect.            `
        });
    }

    req.session.userid=user._id.toString();
    req.session.accoountType=user.accountType;
    
    if (user.accountType === "student") {
        return res.redirect("/student-dashboard");
    }

    if (user.accountType === "recruiter") {
        return res.redirect("/recruiter-dashboard");
    }

    return res.send("Invalid account type");
})
app.post("/forgot-password/send-otp",async (req,res)=>{
    const data=req.body;

    const otp=Math.floor(10000 + Math.random()*90000).toString();
    
    const otpHash=await bcrypt.hash(otp,10);
    const expiry=new Date(Date.now() + 10 * 60 *1000)

    const checkUsers=await db.getdb().collection("users").findOne({email:data.email});

    if(!checkUsers){
        return res.render("auth/login",{
            otpSended:false,otpSendedMsg:"Entered Email is not a user's email."
        })
    }

    const option={
        from: process.env.EMAIL_USER,
        to : data.email,
        subject: "CareerConnect | Password Reset Verification Code",
        text: `
Hello,

We received a request to reset the password associated with your CareerConnect account.

Your verification code is:

${otp}

This code will expire in 10 minutes.

For your security, please do not share this verification code with anyone. CareerConnect will never ask you to provide your OTP by email, phone, or message.

If you did not request a password reset, you can safely ignore this email. Your account will remain unchanged.

Regards,
CareerConnect Security Team
            `
    }

    try {
        req.session.verifyOtp=data.email;
        await db.getdb().collection("otps").deleteMany({
            email: data.email
        });
        await db.getdb().collection("otps").insertOne({email:data.email,otp:otpHash,expiryAt:expiry});
        await transporter.sendMail(option);
        return res.render("auth/login",{
            otpSended:true,otpSendedMsg:"Otp was sent.Check Your Email !"
        })
    }catch(err){
        console.log("Otp send failed.")
        return res.render("auth/login",{
            otpSended:false,otpSendedMsg:"Failed To sent Otp."
        })
    }
})
app.post("/forgot-password/verify-otp",async (req,res)=>{
    const data=req.body;
    const email=req.session.verifyOtp;

    if (!email) {
        return res.render("auth/login",{
            otpSended:false,otpSendedMsg:"Reset session expired. Please request a new OTP."
        })
    }
    const otpData=await db.getdb().collection("otps").findOne({email:email});

    if (!otpData) {
        
        return res.render("auth/login",{
            otpError:true, errorMsg:"Entered Otp Is Expired."
        });
    }
    const {otp,expiryAt}=otpData;

    const currentTime=new Date(Date.now());

    if(currentTime < expiryAt){
        const check=await bcrypt.compare(data.otp,otp);
        if (check) {
            console.log("Otp for password reset was sucessfull.")
            req.session.passwordResetVerified = true;

            await db.getdb().collection("otps").deleteOne({
                _id: otpData._id
            });
            return res.render("auth/login",{
                otpVerified:true
            })
            
        }else{
            console.log("OTP was not correct")
            return res.render("auth/login",{
                otpError:true, errorMsg:"Entered Otp Was Incorrect."
            });
        }
    }else{
        console.log("Otp is expired");
        await db.getdb().collection("otps").deleteOne({_id:otpData._id});
        return res.render("auth/login",{
            otpError:true, errorMsg:"Otp is Expired."
        });
    }
})

app.post("/forgot-password/reset-password",async (req,res)=>{
    const data=req.body;
    const email=req.session.verifyOtp;
    const verified =req.session.passwordResetVerified;
    if(!email || !verified){
        
        return res.send("Password Reset Session Is Expired.")
    }

    if(data.newPassword === data.confirmPassword){
        const hashedPassword = await bcrypt.hash(data.newPassword, 10);
        await db.getdb().collection("users").updateOne({email:email},{$set:{password:hashedPassword}})
        req.session.destroy();
        return res.redirect("/login");
    }else{
        console.log("Password reset was not sucessfull.")
        return res.render("auth/login",{
            resetError:true,resetErrormsg:"New pass and confirm pass doesn't match."
        })
    }


})
app.get("/logout",(req,res)=>{

    req.session.destroy((err)=>{

        if(err){
            console.log(err);
            return res.status(500).render("errors/500");
        }

        res.redirect("/login");

    });

});


app.get("/student-dashboard",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const {name}=await db.getdb().collection("users").findOne({_id:id});
    const data=await db.getdb().collection("applications").find({studentId:id}).sort({appliedDate:-1}).limit(3).toArray();
    const countData=await db.getdb().collection("applications").find({studentId:id}).toArray();
    const count=countData.length;
    const array2=await db.getdb().collection("jobs").find().toArray();
    const first3=await db.getdb().collection("jobs").find().sort({_id:-1}).limit(3).toArray();
    const ssId=new ObjectId(req.session.userid);
    let {email,about,college,degree,graduationYear,location,phone,skills,resume}=await db.getdb().collection("users").findOne({_id:id});
    let array=[name,email,about,degree,graduationYear,location,phone,skills,resume];
    let fieldCompleted=0;
    array.forEach(item=>{
        if(item){
            fieldCompleted+=1;
        }
    })
    const interview=await db.getdb().collection("interviews").find({studentId:id}).toArray();
    let countInter=0;
    for (const item of interview){
        const storeDate=item.interviewDate;
        if(!storeDate){
            
            continue;
        }
        const date=new Date().toISOString().split("T")[0];
        if(date <= storeDate){
            countInter+=1;
        }
    }
    let completionRate=Math.round((fieldCompleted/array.length)*100);
    let array1=[];
    for(const item of data ){
        let jId=item.jobId;
        if(!jId){
            continue;
        }
        const job = await db.getdb().collection("jobs").findOne({ _id: jId });

        if (!job) {
            continue;
        }
        let {jobTitle,company}=await db.getdb().collection("jobs").findOne({_id:jId});
        let appliedDate=item.appliedDate;
        let status=item.status;
        const details={jobTitle:jobTitle,company:company,appliedDate:appliedDate,status:status};
        array1.push(details);
    }
    const data1=await db.getdb().collection("savedJobs").find({studentId:ssId}).toArray();

    const countSave=data1.length;
    const data2=await db.getdb().collection("interviews").find({studentId:ssId}).toArray();
    const countInterview=data2.length;

    const notification=await db.getdb().collection("notifications").find({userId:id}).sort({createdAt:-1}).toArray();
    let unreadCount=0;
    let arrayNotification=[];
    for(const item of notification){
        if(!item.isRead){
            unreadCount+=1;
        }
        const diff=new Date() - new Date(item.createdAt);
        const minutes=Math.floor(diff/(60*1000));
        const hours=Math.floor(diff/(60*60*1000));
        const days=Math.floor(diff/(24*60*60*1000));
        let timeAge="";
        if (minutes < 1){
            timeAge="Just now"
        }else if (minutes <60 ) {
            timeAge=minutes+" "+"minutes ago."
        }else if (hours <24 ){
            timeAge=hours+" "+"hours ago";
        }else if (hours < 48) {
            timeAge="Yesterday"
        }else{
            timeAge=days+" "+"days ago."
        }

        const details={_id:item._id,isRead:item.isRead,type:item.type,title:item.title,message:item.message,createdAt:timeAge};
        arrayNotification.push(details);
    }
    res.render('auth/student-dashboard',{name:name,countInter:countInter,countApplication:count,completionRate:completionRate,array:array1,first3:first3,countSave:countSave,countInterview:countInterview,notification:arrayNotification,unreadCount:unreadCount});
})

app.get("/student/profile",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);

    let {name,email,about,college,degree,graduationYear,location,phone,skills,resume}=await db.getdb().collection("users").findOne({_id:id});

    let array=[name,email,about,degree,graduationYear,location,phone,skills,resume];
    
    let fieldCompleted=0;
    array.forEach(item=>{
        if(item){
            fieldCompleted+=1;
        }
    })

    let completionRate=(fieldCompleted/array.length)*100;
    
    res.render("auth/student-profile",{Name:name,Email:email,about:about,college:college,degree:degree,graduationYear:graduationYear,location:location,phone:phone,skills:skills,rate:completionRate,filename:resume ? resume.fileName:" ",resume});
    
}) 

app.get("/student/profile/edit",Auth,role("student"),async(req,res)=>{
    const id=new ObjectId(req.session.userid);
    const data=await db.getdb().collection("users").findOne({_id:id})
    const {email}=data;
    res.render("edit-student-profile",{email:email});
})

app.post("/student/profile/edit",Auth,role("student"),async (req,res)=>{
    const data=req.body;

    const id=new ObjectId(req.session.userid);

    

    await db.getdb().collection("users").updateOne({_id:id},{$set:data})
    
    res.redirect("/student/profile");


})



const resumeUpload=multer({storage:resumeStorage,limits: {
    fileSize: 6 * 1024 * 1024
}});

app.post("/student/profile/resume",Auth,role("student"),resumeUpload.single("resume"),async (req,res)=>{
  
    const file=req.file;
    
    if(!file){
        return res.send("Resume failed to upload.")
    }

    const id=new ObjectId(req.session.userid);
    let resume={
        fileName:file.originalname,
        url:file.path

    }

    await db.getdb().collection("users").updateOne({_id:id},{$set:{resume:resume}})
    console.log(resume);

    res.redirect("/student/profile");
})

//recuiter-routes

app.get("/recruiter-dashboard",Auth,role("recruiter"),async (req,res)=>{
    const rId=new ObjectId(req.session.userid);
    const {name}=await db.getdb().collection("users").findOne({_id:rId});
    const data=await db.getdb().collection("jobs").find({recruiterId:rId}).toArray();
    const data1=await db.getdb().collection("applications").find({recruiterId:rId}).toArray();
    const shortlist=await db.getdb().collection("applications").find({recruiterId:rId,status:"Shortlist"}).toArray();
    const countJobs=data.length;
    const countApplication=data1.length;
    const countshort=shortlist.length;

    const notification=await db.getdb().collection("notifications").find({userId:rId}).sort({_id:-1}).toArray();
    let unreadCount=0;
    let timeAge="";
    let addNotification=[];
    for(const item of notification){
        const read=item.isRead;
        if(!read){
            unreadCount+=1;
        }

        const diff=new Date() - new Date(item.createdAt);
        const minutes=Math.floor(diff/(60*10000));
        const hours=Math.floor(diff/(60*60*1000));
        const days=Math.floor(diff/(24*660*60*1000));

        if(minutes < 1){
            timeAge="Just Now"
        }else if(minutes < 60){
            timeAge=minutes+" "+"minutes ago"
        }else if(hours < 24){
            timeAge="Yesterday";
        }else{
            timeAge=hours+" "+"hours ago"
        }
        let id=item._id;
        const details={_id:id,isRead:item.isRead,type:item.type,title:item.title,message:item.message,createdAt:timeAge};
        addNotification.push(details);
    }
    const jobCard=await db.getdb().collection("jobs").find({recruiterId:rId}).sort({_id:-1}).limit(4).toArray();
    let array=[];
    for(const item of data){
        const _id= item._id;
        const jobTitle=item.jobTitle;
        const company=item.company;
        const location=item.location;
        const jobType=item.jobType;
        const deadline=item.deadline;

        const details={_id:_id,jobTitle:jobTitle,company:company,location:location,jobType:jobType,deadline:deadline};
        array.push(details);
    }
    res.render("auth/recruiter-dashboard",{name:name,countJobs:countJobs,countApplication:countApplication,countShort:countshort,array:array,unreadCount:unreadCount,notification:addNotification});
})
app.post("/recruiter/notifications/read-all",Auth,role("recruiter"),async (req,res)=>{
    const rId=new ObjectId(req.session.userid);
    const data=await db.getdb().collection("notifications").updateMany({$and:[{userId:rId},{isRead:false}]},{$set:{isRead:true}});

    return res.redirect("/recruiter-dashboard");
})

app.get("/recruiter/notification/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const rId=new ObjectId(req.session.userid);
    const id=new ObjectId(req.params.id);

    const data=await db.getdb().collection("notifications").findOne({userId:rId,_id:id});
    if(!data){
        return res.status(403).render("errors/403"); 
    }
    const {type}=data;

    await db.getdb().collection("notifications").updateOne({$and:[{_id:id},{userId:rId}]},{$set:{isRead:true}});

    return res.redirect("/recruiter/application");


})
app.get("/recruiter/profile",Auth,role("recruiter"),async (req,res)=>{
    
    const id=new ObjectId(req.session.userid);
    const {name,email,about,company,location,phone,website}=await db.getdb().collection("users").findOne({_id:id}); 
    let data=[name,email,about,company,location,phone,website]
    let dataCount=0;

    data.forEach(item =>{
        if(item){
            dataCount+=1;
        }
    })
    let completionRate= (dataCount/data.length)*100;
    res.render("auth/recruiter-profile",{name:name,email:email,about:about,company:company,location:location,phone:phone,website:website,rate:completionRate});
    
    
})

app.get("/recruiter/profile/edit",Auth,role("recruiter"),async (req,res)=>{
    const rId=new ObjectId(req.session.userid);
    const data=await db.getdb().collection("users").findOne({_id:rId});
    const {email}=data;
    res.render("auth/recruiter-profile-edit",{email:email})
})

app.post("/recruiter/profile/edit",Auth,role("recruiter"),async (req,res)=>{
    const data=req.body;
    const id=new ObjectId(req.session.userid);
    const allData={
        name:data.name,
        about:data.about,
        location:data.location,
        company:data.company,
        website:data.website,
        phone:data.phone
    }
    await db.getdb().collection("users").updateOne({_id:id},{$set:allData});

    res.redirect("/recruiter/profile")
})

// post job
app.get("/recruiter/job/post",Auth,role("recruiter"),(req,res)=>{
    res.render("jobs/post-job");
})

app.post("/recruiter/job/post",Auth,role("recruiter"),async (req,res)=>{
    const data=req.body;
    const id=new ObjectId(req.session.userid);
    const date=new Date().toISOString().split("T")[0];
    const jobData={recruiterId:id,...data,status:"Applied",postDate:date};
    await db.getdb().collection("jobs").insertOne(jobData);
    res.redirect("/recruiter/profile");
})
//see job in my jobs

app.get("/recruiter/jobs",Auth,role("recruiter"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const data=await db.getdb().collection("jobs").find({recruiterId:id}).toArray(); 
    const message=req.session.message || null;
    delete req.session.message;
    
    res.render("jobs/recruiter-jobs",{data:data,message:message});
})

//view jobs
app.get("/recruiter/job/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const jobId = new ObjectId(req.params.id);
    const recruiterId = new ObjectId(req.session.userid);

    const data = await db.getdb().collection("jobs").findOne({
        _id: jobId,
        recruiterId: recruiterId
    });

    if(!data){
        return res.send("Access Denied");
    }

    res.render("jobs/recruiter-job-view",{data:data});
})

//edit jobs

app.get("/recruiter/job/edit/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const jobId = new ObjectId(req.params.id);
    const recruiterId = new ObjectId(req.session.userid);

    const data = await db.getdb().collection("jobs").findOne({
        _id: jobId,
        recruiterId: recruiterId
    });

    if(!data){
        return res.send("Access Denied");
    }

    res.render("jobs/recruiter-job-edit",{data:data});
})

app.post("/recruiter/job/edit/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const jobId = new ObjectId(req.params.id);
    const recruiterId = new ObjectId(req.session.userid);

    const data = req.body;

    const allData = {
        jobTitle:data.jobTitle,
        company:data.company,
        location:data.location,
        jobType:data.jobType,
        experience:data.experience,
        salary:data.salary,
        deadline:data.deadline,
        skills:data.skills,
        responsibilities:data.responsibilities,
        qualifications:data.qualifications
    }

    const result = await db.getdb().collection("jobs").updateOne(
        {
            _id: jobId,
            recruiterId: recruiterId
        },
        {
            $set: allData
        }
    );

    if(result.matchedCount === 0){
        return res.status(403).render("errors/403");
    }

    res.redirect("/recruiter/jobs");
})

app.get("/recruiter/job/delete/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const id= new ObjectId(req.params.id);
    const userid=new ObjectId(req.session.userid);
    const found=await db.getdb().collection("jobs").findOne({_id:id,recruiterId:userid});
    if (!found) {
        req.session.message = "Job not found. It may have already been deleted.";
        return res.redirect("/recruiter/jobs");
    }

    const {recruiterId}=found;
    const application=await db.getdb().collection("applications").find({$and:[{jobId:id},{recruiterId:userid}]}).toArray();
    
    if(userid.equals(recruiterId)){
        for(const item of application){
            const aId=item._id;
            await db.getdb().collection("interviews").deleteOne({applicationId:aId});
            await db.getdb().collection("applications").deleteOne({_id:aId});
        }
        await db.getdb().collection("jobs").deleteOne({_id:id,recruiterId:recruiterId});
        await db.getdb().collection("savedJobs").deleteOne({jobId:id})
        
        res.redirect("/recruiter/jobs");
    }else{
        res.send("Delete access deneied")
        
    }
})

//student-seeing-jobs

app.get("/student-jobs",Auth,role("student"),async (req,res)=>{

    const page=parseInt(req.query.page) || 1;

    const search=req.query.search;
    const loaction=req.query.location;
    const loactionArray = Array.isArray(loaction) ? loaction : [loaction];
    const locationSearch=req.query.locationSearch;
    const jobType = req.query.jobType;
    const jobTypeArray = Array.isArray(jobType) ? jobType : [jobType];
    const experience = req.query.experience;

    const message=req.session.messageStudent || null;
    delete req.session.messageStudent;
    
    let filter={};

    if(search){
        filter.$or=[
            {
                jobTitle: {
                    $regex: search,
                    $options: "i"
                }
            },
            {
                company: {
                    $regex: search,
                    $options: "i"
                }
            },
            {
                skills: {
                    $regex: search,
                    $options: "i"
                }
            }
        ];
    }
    if(loaction){
        filter.location={
            $in:loactionArray
        }
    };
    if(locationSearch){
        if(filter.location){
            filter.$and=[{
                location:{
                    $in:loactionArray
                }
            },{location:{$regex:locationSearch,$options:"i"}}]

            delete filter.location;
        }else{
            filter.location={
                $regex:locationSearch,
                $options:"i"
            }
        }
    }

    if(jobType){
        filter.jobType={
            $in:jobTypeArray
        }
    }

    if(experience){
        filter.experience={
            $regex:experience,
            $options:"i"
        }
    }
    const array=await db.getdb().collection("jobs").find(filter).toArray();
    const totalJobs=array.length;
    const  jobsPerPage=6;
    const totalPage=Math.ceil(totalJobs/jobsPerPage);
    const skip=(page-1) * jobsPerPage;

    
    const data=await db.getdb().collection("jobs").find(filter).sort({_id:-1}).skip(skip).limit(jobsPerPage).toArray();
    res.render("student-jobs/student-jobs",{data:data,currentPage:page,totalPage:totalPage,message:message});
})

app.get("/student/job-view/:id",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.params.id);

    const data=await db.getdb().collection("jobs").findOne({_id:id});

    if(!data){
        req.session.messageStudent="Job not found. It may have already been deleted.";
        return res.redirect("/student-jobs")
    }

    res.render("student-jobs/student-job-view",{data:data});
})

app.get("/student/job/apply/:id",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.params.id);

    const data=await db.getdb().collection("jobs").findOne({_id:id});

    if(!data){
        return res.send("Job not found");
    }
    
    res.render("student-jobs/student-job-apply",{id:id,data:data});
})

//multer for apply resume
const store=multer.diskStorage({
    filename:(req,file,cb)=>{
        cb(null,Date.now()+'-'+file.originalname);
    },
    destination:(req,file,cb)=>{
        cb(null,'public/uploads/apply-resumes');
    }
})

const uploaded=multer({storage:store})
app.post("/student/job/apply/:id",uploaded.single("resume"),async (req,res)=>{
    const cover=req.body;
    const jId=new ObjectId(req.params.id);
    const sId=new ObjectId(req.session.userid);
    const check=await db.getdb().collection("applications").findOne({$and:[{studentId:sId},{jobId:jId}]})
    if(check){
        return res.send("Already Applied To This Job.")
    }

    const data=req.file;
    if(!data){
        return res.send("Please upload resume")
    }
    const date=new Date().toISOString().split('T')[0];
    const {recruiterId,jobTitle}=await db.getdb().collection("jobs").findOne({_id:jId});
    const recruiter=await db.getdb().collection("users").findOne({_id:recruiterId});
    const student=await db.getdb().collection("users").findOne({_id:sId});

    const {name,email}=student;
    const {name:nameR,email:emailR}=recruiter;
    const option = {
        from: process.env.EMAIL_USER,
        to: emailR,
        subject: `New Application Received - ${jobTitle}`,
        text: `
    Hello Mr.${nameR} !,

    You have received a new application on CareerConnect.

    Job: ${jobTitle}
    Candidate: ${name}
    Candidate Email: ${email}
    Applied Date: ${date}

    Please log in to your CareerConnect recruiter dashboard to review the application.

    Regards,
    CareerConnect Team
            `

    }
    const file={
        Name:data.filename,
        destination:data.destination
    }

    await db.getdb().collection("applications").insertOne({jobId:jId,studentId:sId,recruiterId:recruiterId,file,appliedDate:date,coverLetter:cover.coverLetter,status:"Applied",interview:"No"});
    const message = `${name} has applied for the ${jobTitle} position.`;
    await db.getdb().collection("notifications").insertOne({
        userId: recruiterId,
        type: "NewApplication",
        title: "New Application",
        message: message,
        relatedId: jId,
        isRead: false,
        createdAt: new Date()
    })
    try{
        await transporter.sendMail(option);
        console.log("Email sent succesfully");
    }catch(err){
        if(err){
            console.log("Email not sent succesfully:-",err);
        }
    }
    res.redirect("/student-jobs");
})

app.get("/recruiter/application",Auth,role("recruiter"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    
    const data=await db.getdb().collection("applications").find({recruiterId:id}).toArray();
    
    let array=[];
    const totalApplication=data.length;
    for (const item of data){
        const sId=item.studentId;
        const jId=item.jobId;
        const {name,email}=  await db.getdb().collection("users").findOne({_id:sId});
        const {jobTitle}= await  db.getdb().collection("jobs").findOne({_id:jId});
        let date=item.appliedDate;
        let status=item.status;
        let id=item._id;
        let details={name:name,email:email,title:jobTitle,appliedDate:date,id:id,status:status};
        array.push(details);
    }
    
    res.render("application/recruiter-applications",{array:array,totalApplication:totalApplication});
})

//view-application
app.get("/recruiter/view/application/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const id=new ObjectId(req.params.id);
    const rId=new ObjectId(req.session.userid);
    
    const application=await db.getdb().collection("applications").findOne({$and:[{_id:id},{recruiterId:rId}]});

    if(!application){
        return res.status(403).render("errors/403");
    };
    const {jobId,studentId,appliedDate,coverLetter,file,interview,status}=application;
    const {jobTitle,company}=await db.getdb().collection("jobs").findOne({_id:jobId})
    const sId=studentId;
    const {name,email}=await db.getdb().collection("users").findOne({_id:sId});

    res.render("application/recruiter-application-view",{name:name,email:email,jobTitle:jobTitle,company:company,appliedDate:appliedDate,coverLetter:coverLetter,file:file,_id:id,interview:interview,status:status});
})
//shortlist
app.get("/recruiter/application/REJECT/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const aId = new ObjectId(req.params.id);
    const rId = new ObjectId(req.session.userid);

    const application = await db.getdb().collection("applications").findOne({
        _id: aId,
        recruiterId: rId
    });

    if(!application){
        return res.status(403).render("errors/403");
    }

    const {studentId,jobId}=application;
    const {name,email}=await db.getdb().collection("users").findOne({
        _id: studentId,
    });
    const  {jobTitle,company}=await db.getdb().collection("jobs").findOne({
        _id: jobId,
    });
    const option ={
        from:process.env.EMAIL_USER,
        to: email,
        subject: `Application Update - ${jobTitle} `,
        text: `
Hello ${name}!,

Thank you for applying for the ${jobTitle} position through CareerConnect.

We wanted to let you know that your application has not been selected for the next stage of the recruitment process.

We encourage you to continue exploring other opportunities available on CareerConnect.

Regards,
CareerConnect Team 
            `   
    }


    await db.getdb().collection("applications").updateOne(
        {
            _id: aId,
            recruiterId: rId
        },
        {
            $set:{
                status:"Reject"
            }
        }
    );

    const message= `Thank you for your interest in ${jobTitle} at ${company}. Unfortunately, your application was not selected for the next stage.`;;
    const date= new Date();

    await db.getdb().collection("notifications").insertOne({
        userId:studentId,type:"Reject",
        title: "Application Status Update",message:message,isRead:false,
        relatedId:aId,createdAt:date,
    })

    try{
        await transporter.sendMail(option)
        console.log("Email-sent suceesfully");
    }catch(err){
        console.log("Email not sent successfully")
    }

    res.redirect("/recruiter/application");
})

app.get("/recruiter/application/SHORTLIST/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const aId = new ObjectId(req.params.id);
    const rId = new ObjectId(req.session.userid);

    const application = await db.getdb().collection("applications").findOne({
        _id: aId,
        recruiterId: rId
    });

    if (!application) {
        return res.status(403).render("errors/403");
    }

    const {studentId,jobId}=application;
    const {name,email}=await db.getdb().collection("users").findOne({
        _id: studentId,
    });
    const  {jobTitle,company}=await db.getdb().collection("jobs").findOne({
        _id: jobId,
    });
    const option ={
        from:process.env.EMAIL_USER,
        to: email,
        subject: `Application Update - ${jobTitle} `,
        text: `
Hello ${name}!,

Great news! Your application for ${jobTitle} has been shortlisted.

The recruiter has moved your application to the next stage of the hiring process.

Please keep checking CareerConnect for interview updates.

Regards,
CareerConnect Team 
            `   
    }


    await db.getdb().collection("applications").updateOne(
        {
            _id: aId,
            recruiterId: rId
        },
        {
            $set: {
                status: "Shortlist",
                interview: "no"
            }
        }
    );

    const message= `Congratulations! Your application for ${jobTitle} at ${company} has been shortlisted.`;
    const date= new Date();

    await db.getdb().collection("notifications").insertOne({
        userId:studentId,type:"Shortlist",
        title: "Application Shortlisted",message:message,isRead:false,
        relatedId:aId,createdAt:date,
    })

    

    try{
        await transporter.sendMail(option)
        console.log("Email-sent suceesfully");
    }catch(err){
        console.log("Email not sent successfully")
    }

    res.redirect("/recruiter/application");
})

app.get("/recruiter/interview/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    
    const aId = new ObjectId(req.params.id);
    const rId = new ObjectId(req.session.userid);

    const messagee=req.session.messageR2 || null;
    delete req.session.messageR2;

    const application = await db.getdb().collection("applications").findOne({
        _id: aId,
        recruiterId: rId
    });

    if (!application) {
        return res.status(403).render("errors/403");
    }

    const data = await db.getdb().collection("interviews").findOne({
        applicationId: aId,
        recruiterId: rId
    });

    const { studentId, jobId } = application;

    const { name, email } = await db.getdb().collection("users").findOne({
        _id: studentId
    });

    const { jobTitle } = await db.getdb().collection("jobs").findOne({
        _id: jobId
    });

    res.render("application/recruiter-interview", {
        name: name,
        email: email,
        jobTitle: jobTitle,
        _id: aId,
        jobId: jobId,
        data: data,
        fillupData:data,message:messagee
    });
})
app.post("/recruiter/interview/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const data=req.body;
    const aId=new ObjectId(req.params.id);
    const rId=new ObjectId(req.session.userid);
    const application =await db.getdb().collection("applications").findOne({$and:[{_id:aId},{recruiterId:rId}]});

    

    if(!application){
        return res.status(403).render("errors/403");
    };
    const {status}=application;
    const {studentId,jobId}=application;
    const details={
        interviewDate:data.interviewDate,
        interviewTime:data.interviewTime,
        interviewMode:data.interviewMode,
        location:data.location,
        notes:data.notes
    }
    const date=new Date().toISOString().split("T")[0];
    const duplicate=await db.getdb().collection("interviews").findOne({$and:[{applicationId:aId,recruiterId:rId}]});
    if(duplicate){
        return res.redirect("/recruiter/application");
    }
    if (status) {
        await db.getdb().collection("interviews").insertOne({ applicationId: aId, studentId: studentId, recruiterId: rId, fillupDate: date, ...details });
        await db.getdb().collection("applications").updateOne({ _id: aId,recruiterId:rId }, { $set: { interview: 'yes' } });
    }
    const {name,email}=await db.getdb().collection("users").findOne({_id:studentId});
    const {jobTitle,company}=await db.getdb().collection("jobs").findOne({_id:jobId});
    const option={
        from:process.env.EMAIL_USER,
        to:email,
        subject:`Interview Scheduled - ${jobTitle}`,
        text:`
Hello ${name},

Your interview for the ${jobTitle} position has been scheduled.

Interview Details:

Date: ${data.interviewDate}
Time: ${data.interviewTime}
Mode: ${data.interviewMode}
Location: ${data.location || "Not specified"}
Notes: ${data.notes || "No additional notes"}

Please make sure to be available at the scheduled time.

Regards,
CareerConnect Team
            `
    }

    const title = "Interview Scheduled";
    const message = `Your interview for ${jobTitle} at ${company} has been scheduled for ${data.interviewDate} at ${data.interviewTime}. Please review the interview details and be prepared on time.`;
    
    await db.getdb().collection("notifications").insertOne({
        userId:studentId,type:"Interview",
        title:title,message:message,
        isRead:false,createdAt:new Date(),
        relatedId:aId
    })

    try{
        await transporter.sendMail(option)
        console.log("Email sent succesfully.")
    }catch(err){
        console.log("Email not sent succesfully.",err);
    }

    res.redirect("/recruiter/application");
})

app.get("/recruiter/interview/edit/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    
    const aId = new ObjectId(req.params.id);
    const rId = new ObjectId(req.session.userid);

    const message=req.session.messageR2 || null;
    delete req.session.messageR2;

    const application = await db.getdb().collection("applications").findOne({
        _id:aId,
        recruiterId:rId
    });

    if(!application){
        return res.status(403).render("errors/403");
    }

    const data = await db.getdb().collection("interviews").findOne({
        applicationId:aId,
        recruiterId:rId
    });

    if(!data){
        return res.redirect("/recruiter/application");
    }

    const {studentId,jobId} = application;

    const {name,email} = await db.getdb().collection("users").findOne({
        _id:studentId
    });

    const {jobTitle} = await db.getdb().collection("jobs").findOne({
        _id:jobId
    });
   
    res.render("application/recruiter-interview",{
        name:name,
        email:email,
        jobTitle:jobTitle,
        _id:aId,
        jobId:jobId,
        data:"",
        fillupData:data,message:message
    });
})
app.post("/recruiter/interview/edit/:id",Auth,role("recruiter"),checkObjectId,async (req,res)=>{
    const interviewId = new ObjectId(req.params.id);
    const rId = new ObjectId(req.session.userid);
    
    const { interviewDate,
        interviewTime,
        interviewMode,
        location
        , notes } = req.body;


    const currentDate = new Date().toISOString().split("T")[0];

    if (interviewDate < currentDate) {
        req.session.messageR2="Please Select Current Date"
        return res.redirect(`/recruiter/interview/edit/${interviewId}`);
    }
    const result = await db.getdb().collection("interviews").updateOne(
        {
            _id:interviewId,
            recruiterId:rId
        },
        {
            $set:{interviewDate:interviewDate,
            interviewTime:interviewTime,
            interviewMode:interviewMode,
            location:location,
            notes:notes}
        }
    );

    if(result.matchedCount === 0){
        return res.send("Access Denied");
    }

    const {studentId,applicationId,interviewDate:interviewDate1,interviewTime:interviewTime1,interviewMode:interviewMode1,location:location1,notes:notes1}=await db.getdb().collection("interviews").findOne({_id:interviewId});
    const {jobId}=await db.getdb().collection("applications").findOne({_id:applicationId});
    const {name,email}=await db.getdb().collection("users").findOne({_id:studentId});
    const {jobTitle,company}=await db.getdb().collection("jobs").findOne({_id:jobId});
    const option={
        from:process.env.EMAIL_USER,
        to:email,
        subject:`Interview Scheduled - ${jobTitle}`,
        text:`
Hello ${name},

Your interview for the ${jobTitle} position has been Re-scheduled.

Interview Details:

Date: ${interviewDate1}
Time: ${interviewTime1}
Mode: ${interviewMode1}
Location: ${location1 || "Not specified"}
Notes: ${notes1 || "No additional notes"}

Please make sure to be available at the scheduled time.

Regards,
CareerConnect Team
            `
    }

    const message =
    `Your interview details for ${jobTitle} at ${company} have been updated. Please review the latest schedule.`;
     
    await db.getdb().collection("notifications").insertOne({
        userId:studentId,type:"InterviewUpdate",
        title:"Interview Updated",message:message,
        isRead:false,createdAt:new Date(),
        relatedId:applicationId,
    })

    try{
        await transporter.sendMail(option)
        console.log("Email sent succesfully.")
    }catch(err){
        console.log("Email not sent succesfully.",err);
    }

    res.redirect("/recruiter/application");
})

app.get("/student/application",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const data=await db.getdb().collection("applications").find({studentId:id}).toArray();
    let count=0;;
    let array=[];
    let countReject=0;
    let countShort=0;
    let countApplied=0;
    for (const item of data){
        let jID=item.jobId;
        let aId=item._id;
        const check=await db.getdb().collection("jobs").findOne({_id:jID});
        if(!check){
            continue;
        }
        let appliedDate=item.appliedDate;
        let status=item.status;
        const {jobTitle,company,location}=check;
        if(status==='Reject'){
            countReject+=1;
        }
        if(status==='Shortlist'){
            countShort+=1;
        }
        if(status==='Applied'){
            countApplied+=1;
        }
        const details={appliedDate:appliedDate,status:status,jobTitle:jobTitle,company:company,location:location,_id:aId};
        array.push(details);
        count+=1;
    }
    res.render("application/student-applications",{array:array,count:count,countReject:countReject,countShort:countShort,countApplied:countApplied});
})

app.get("/student/application/cancel/:id",Auth,role("student"),checkObjectId,async (req,res)=>{
    const aId=new ObjectId(req.params.id);
    const sId=new ObjectId(req.session.userid);
    const application=await db.getdb().collection("applications").findOne({_id:aId,studentId:sId});
    const student=await db.getdb().collection("users").findOne({_id:sId});
    const {name}=student;
    if(!application){
        return res.status(403).render("errors/403");
    }

    const {status,jobId} = application;
    const {jobTitle,recruiterId}=await db.getdb().collection("jobs").findOne({_id:jobId});
    if( (status==="Reject" || status==="Applied")){
        const data=await db.getdb().collection("interviews").findOne({applicationId:aId,studentId:sId});
        if(data){
            await db.getdb().collection("interviews").deleteOne({applicationId:aId,studentId:sId});
        }
        const message=`${name} has withdrawn their application for the ${jobTitle} position.`;
        await db.getdb().collection("notifications").insertOne({
            userId: recruiterId,
            type: "ApplicationWithdrawn",
            title: "Withdrawn Application",
            message: message,
            relatedId: jobId,
            isRead: false,
            createdAt: new Date()
        })
        await db.getdb().collection("applications").deleteOne({_id:aId,studentId:sId});
        return res.redirect("/student/application")
    }else{
        return res.status(403).render("errors/403");
    }
})

app.get("/student/job/saved/:id",Auth,role("student"),checkObjectId,async (req,res)=>{
    const jId=new ObjectId(req.params.id);
    const sId=new ObjectId(req.session.userid);

    const job=await db.getdb().collection("jobs").findOne({_id:jId});

    if(!job){
        req.session.messageS2="Job not found. It may have already been deleted."
        return res.redirect("/student-saved-jobs")
    }

    const alreadySaved=await db.getdb().collection("savedJobs").findOne({
        jobId:jId,
        studentId:sId
    });

    if(alreadySaved){
        req.session.messageSjob="Job is already saved.!"
        return res.redirect("/student-saved-jobs");
    }

    await db.getdb().collection("savedJobs").insertOne({
        studentId:sId,
        jobId:jId
    });

    res.redirect("/student-dashboard");
})

app.get("/student-saved-jobs",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const data=await db.getdb().collection("savedJobs").find({studentId:id}).toArray();
    let count=0;
    const message=req.session.messageS2 || req.session.messageSjob || null;
    delete req.session.messageS2;
    delete req.session.messageSjob;

    let array=[];
    for (const item of data) {
        const jId = item.jobId
        const job = await db.getdb().collection("jobs").findOne({
            _id: jId
        });

        if (!job) {
            continue;
        }

        const { jobTitle, company, location, jobType, salary } = job;
        const details={jobTitle:jobTitle,company:company,location:location,salary:salary,id:jId};
        array.push(details);
        count+=1;
    }
    res.render("student-jobs/student-saved-jobs",{array:array,countSave:count,message:message});
})
app.get("/student/remove-job/:id",Auth,role("student"),checkObjectId,async (req,res)=>{
    const id=new ObjectId(req.params.id);
    const sId=new ObjectId(req.session.userid);
    await db.getdb().collection("savedJobs").deleteOne({$and:[{jobId:id},{studentId:sId}]});
    res.redirect("/student-saved-jobs");
})

app.get("/student/interview",Auth,role("student"),async (req,res)=>{
    const sId=new ObjectId(req.session.userid);
    const data=await db.getdb().collection("interviews").find({studentId:sId}).toArray();
    let count=0;
    let array=[];
    for (const item of data) {
        let aId = item.applicationId;
        const application = await db.getdb().collection("applications").findOne({
            _id: aId,studentId:sId
        });

        if (!application) {
            continue;
        }

        const { jobId } = application;

        const job = await db.getdb().collection("jobs").findOne({
            _id: jobId
        });

        if (!job) {
            continue;
        }

        const { jobTitle, company } = job;
        const details={...item,jobTitle:jobTitle,company:company};
        array.push(details);
        count=+1;
    }
    res.render("application/student-interviews",{array:array,count:count});
})



app.get("/student/setting",Auth,role("student"),async (req,res)=>{
    const sId=new ObjectId(req.session.userid);
    const {name,email}=await db.getdb().collection("users").findOne({_id:sId});
    res.render("auth/student-settings",{name:name,email:email});
})
app.get("/student/change-password",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const data=await db.getdb().collection("users").findOne({_id:id});

    if(!data){
        return res.status(403).render("errors/403")
    }
    const {email}=data;
    res.render("auth/student-change-password",{passConfirm:true,currentPass:true,email:email});
})
app.post("/student/change-password",Auth,role("student"),async (req,res)=>{
    const data=req.body;
    const sId=new ObjectId(req.session.userid);

    const pass=await db.getdb().collection("users").findOne({_id:sId});

    if(!pass){
        return res.status(403).render("errors/403")
    }

    const {password}=pass;
    const check= await bcrypt.compare(data.currentPassword,password);

    if(check){
        if(data.newPassword === data.confirmPassword){
            const newPass=await bcrypt.hash(data.confimrPassword,10);
            await db.getdb().collection("users").updateOne({_id:sId},{$set:{password:newPass}});
            return res.redirect("/student/setting");
        }else{
            return res.render("auth/student-change-password",{passConfirm:false,currentPass:true});
        }
    }else{
        return res.render("auth/student-change-password",{currentPass:false,passConfirm:true});
    }
})

app.post("/student/send-password-otp",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);

    const data=await db.getdb().collection("users").findOne({_id:id});

    const {email}=data;
    const otp=Math.floor(10000 + Math.random()*90000).toString();

    const otpHash=await bcrypt.hash(otp,10);

    const expire=new Date(Date.now() + 10*60*1000);
    const option={
        from: process.env.EMAIL_USER,
        to : email,
        subject: "CareerConnect | Password Reset Verification Code",
        text: `
Hello,

We received a request to reset the password associated with your CareerConnect account.

Your verification code is:

${otp}

This code will expire in 10 minutes.

For your security, please do not share this verification code with anyone. CareerConnect will never ask you to provide your OTP by email, phone, or message.

If you did not request a password reset, you can safely ignore this email. Your account will remain unchanged.

Regards,
CareerConnect Security Team
            `
    }

    try{
        req.session.otpVerified = false;
        await db.getdb().collection("otps").deleteMany({email:email});
        await db.getdb().collection("otps").insertOne({email:email,otp:otpHash,expiryAt:expire});
        await transporter.sendMail(option);
        return res.render("auth/student-change-password",{
            otpSended:true,otpSendedMsg:"Otp is Sent! Please check your email.",email:email
        })
    }catch(err){
        return res.render("auth/student-change-password",{
            otpSended:false,otpSendedMsg:"Failed to send otp."
        })
    }
})

app.post("/student/change-password/verify-otp",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const data=req.body;
    const user=await db.getdb().collection("users").findOne({_id:id});
    const {email}=user;
    const otpStore=await db.getdb().collection("otps").findOne({email:email});
    if (!otpStore) {
        return res.render("auth/student-change-password", {
            email: email,
            otpVerified: false,
            otpVerifiedMsg: "OTP session not found. Please request a new OTP."
        });
    }
    const {otp,expiryAt}=otpStore;
     
    const currentTime=new Date(Date.now());

    if (currentTime < expiryAt) {
        const check = await bcrypt.compare(data.otp, otp);

        if (check) {
            req.session.otpVerified = true;
            await db.getdb().collection("otps").deleteOne({email:email});
            return res.render("auth/student-change-password", {
                otpVerified: true,email:email
            })
        } else {
            return res.render("auth/student-change-password", {
                otpVerified: false, otpVerifiedMsg: "Entered Incorrect Otp."
            })
        }
    } else {
        return res.render("auth/student-change-password", {
            otpVerified: false, otpVerifiedMsg: "Otp is expired.Please Genearate New Otp."
        })
    }
    
})

app.post("/student/change-password/reset-with-otp",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const verified=req.session.otpVerified;
    const data=req.body;
    if(!verified){
        return res.render("auth/student-change-password", {
            otpVerified: false, otpVerifiedMsg: "Password Session is expired.Please generate new otp"
        })
    }
    const user=await db.getdb().collection("users").findOne({_id:id});
    const {email}=user;
    if(data.newPassword === data.confirmPassword){
        const hash=await bcrypt.hash(data.newPassword,10);
        await db.getdb().collection("users").updateOne({_id:id},{$set:{password:hash}});
        delete req.session.otpVerified;
        return res.redirect("/student/setting");
    }else{
        console.log("Password reset failed")
        return res.render("auth/student-change-password",{
            confirmPass:false,confirmPassMsg:"Entered Password Doesn't Match! Re-enter password.",email:email
        });
    }
})

app.post("/student/change-email/send-otp",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const body=req.body;

    const data=await db.getdb().collection("users").findOne({_id:id});

    const {email,name}=data;

    const otp=Math.floor(10000 + Math.random()*90000).toString();

    const otpHash=await bcrypt.hash(otp,10);

    const expires=new Date(Date.now() + 10*60*1000);
    const option={
        from: process.env.EMAIL_USER,
        to : body.newEmail,
        subject: "CareerConnect | Email Change Verification Code",
        text: `
Hello,

We received a request to change the email associated with your CareerConnect account.

Your verification code is:

${otp}

This code will expire in 10 minutes.

For your security, please do not share this verification code with anyone. CareerConnect will never ask you to provide your OTP by email, phone, or message.

If you did not request a password reset, you can safely ignore this email. Your account will remain unchanged.

Regards,
CareerConnect Security Team
            `
    }

    const alreadyUsed = await db.getdb().collection("users").findOne({
        email: body.newEmail
    });
    
    if (alreadyUsed) {
        return res.render("auth/student-settings", {
            emailDuplicate: true, msg: "Enter A New E-mail.",name:name,email:email
        })
    }
    if(email === body.newEmail) {
        return res.render("auth/student-settings",{
            emailDuplicate:true , msg:"Enter A New E-mail.",name:name,email:email
        })
    }else{
        try {
            req.session.verifyOtp = false;
            await db.getdb().collection("otps").deleteMany({ email: email });
            await db.getdb().collection("otps").insertOne({ email: email, otp: otpHash, expiryAt: expires });
            await transporter.sendMail(option);
            req.session.newEmail=body.newEmail;
            return res.render("auth/student-settings",{
                sendingOtp:true,name:name,email:email
            })
        } catch (err) {
            console.log("Error in sending otp :", err);
            return res.render("auth/student-settings", {
                sendingOtp: false, msg: "Failed to send otp.",name:name,email:email
            })
        }
       
    }
})

app.post("/student/change-email/verify-otp",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const verified=req.session.verifyOtp;
    const body=req.body;
    const data=await db.getdb().collection("users").findOne({_id:id});
    const {name,email}=data;
    const otpStore=await db.getdb().collection("otps").findOne({email:email});
    const newEmail=req.session.newEmail;
    if(  !otpStore || !newEmail){
        return res.render("auth/student-settings",{
            otpVerified:false,msg:"Email Reset Session Is Expired.Pls generate new otp.",name:name,email:email
        })
    }

    const {otp,expiryAt}=otpStore;
    const check =await bcrypt.compare(body.otp,otp);

    const currentTime=new Date(Date.now());

    if(currentTime < expiryAt){
        if(check){
            req.session.verifyOtp=true;
            await db.getdb().collection("users").updateOne({_id:id},{$set:{email:newEmail}});
            await db.getdb().collection("otps").deleteOne({_id:otpStore._id})
            delete req.session.newEmail;
            delete req.session.verifyOtp;
            return res.render("auth/student-settings",{
                name:name,email:email
            })
        } else {
            return res.render("auth/student-settings", {
                otpVerified: false, msg: "Entered Otp Is Incorrect.",name:name,email:email
            }) 
        }
    }else{
        await db.getdb().collection("otps").deleteOne({_id:otpStore._id})
        return res.render("auth/student-settings",{
            otpVerified:false,msg:"Otp is expired.Generate new otp.",name:name,email:email
        })
    }

})

app.post("/student/notifications/read-all",Auth,role("student"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);

    await db.getdb().collection("notifications").updateMany({$and:[{userId:id},{isRead:false}]},{
        $set:{isRead:true}
    })
    return res.redirect("/student-dashboard");
});

app.get("/student/notification/:id",Auth,role("student"),checkObjectId,async (req,res)=>{
    const sId=new ObjectId(req.session.userid);
    const nId=new ObjectId(req.params.id);

    const data=await db.getdb().collection("notifications").findOne({_id:nId,userId:sId});

    if(!data){
        return res.send("Acess Denied");
    }
    const {type}=data;
    await db.getdb().collection("notifications").updateOne({_id:data._id},{$set:{isRead:true}});
    
    if(type==="Shortlist" || type ==="Reject"){
        return res.redirect("/student/application");
    }else{
        return res.redirect("/student/interview");
    }
})

app.get("/recruiter/settings",Auth,role("recruiter"),async (req,res)=>{
    const sId=new ObjectId(req.session.userid);
    const {name,email}=await db.getdb().collection("users").findOne({_id:sId});
    res.render("auth/recruiter-setting",{name:name,email:email});
})

app.get("/recruiter/change-password",Auth,role("recruiter"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const data=await db.getdb().collection("users").findOne({_id:id});

    if(!data){
        return res.status(403).render("errors/403");
    }
    const {email}=data;
    res.render("auth/recruiter-change-password",{passConfirm:true,currentPass:true,email:email});
})
app.post("/recruiter/change-password",Auth,role("recruiter"),async (req,res)=>{
    const data=req.body;
    const sId=new ObjectId(req.session.userid);

    const pass=await db.getdb().collection("users").findOne({_id:sId});

    if(!pass){
        return res.status(403).render("errors/403");
    }

    const {password}=pass;
    const check= await bcrypt.compare(data.currentPassword,password);

    if(check){
        if(data.newPassword === data.confirmPassword){
            console.log(req.body);
            const newPass=await bcrypt.hash(data.newPassword,10);
            await db.getdb().collection("users").updateOne({_id:sId},{$set:{password:newPass}});
            return res.redirect("/recruiter/settings");
        }else{
            return res.render("auth/recruiter-change-password",{passConfirm:false,currentPass:true});
        }
    }else{
        return res.render("auth/recruiter-change-password",{currentPass:false,passConfirm:true});
    }
})

app.post("/recruiter/send-password-otp",Auth,role("recruiter"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);

    const data=await db.getdb().collection("users").findOne({_id:id});

    const {email}=data;
    const otp=Math.floor(10000 + Math.random()*90000).toString();

    const otpHash=await bcrypt.hash(otp,10);

    const expire=new Date(Date.now() + 10*60*1000);
    const option={
        from: process.env.EMAIL_USER,
        to : email,
        subject: "CareerConnect | Password Reset Verification Code",
        text: `
Hello,

We received a request to reset the password associated with your CareerConnect account.

Your verification code is:

${otp}

This code will expire in 10 minutes.

For your security, please do not share this verification code with anyone. CareerConnect will never ask you to provide your OTP by email, phone, or message.

If you did not request a password reset, you can safely ignore this email. Your account will remain unchanged.

Regards,
CareerConnect Security Team
            `
    }

    try{
        req.session.otpVerified = false;
        await db.getdb().collection("otps").deleteMany({email:email});
        await db.getdb().collection("otps").insertOne({email:email,otp:otpHash,expiryAt:expire});
        await transporter.sendMail(option);
        return res.render("auth/recruiter-change-password",{
            otpSended:true,otpSendedMsg:"Otp is Sent! Please check your email.",email:email
        })
    }catch(err){
        return res.render("auth/recruiter-change-password",{
            otpSended:false,otpSendedMsg:"Failed to send otp."
        })
    }
})

app.post("/recruiter/change-password/verify-otp",Auth,role("recruiter"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const data=req.body;
    const user=await db.getdb().collection("users").findOne({_id:id});
    const {email}=user;
    const otpStore=await db.getdb().collection("otps").findOne({email:email});
    if (!otpStore) {
        return res.render("auth/recruiter-change-password", {
            email: email,
            otpVerified: false,
            otpVerifiedMsg: "OTP session not found. Please request a new OTP."
        });
    }
    const {otp,expiryAt}=otpStore;
     
    const currentTime=new Date(Date.now());

    if (currentTime < expiryAt) {
        const check = await bcrypt.compare(data.otp, otp);

        if (check) {
            req.session.otpVerified = true;
            await db.getdb().collection("otps").deleteOne({email:email});
            return res.render("auth/recruiter-change-password", {
                otpVerified: true,email:email
            })
        } else {
            return res.render("auth/recruiter-change-password", {
                otpVerified: false, otpVerifiedMsg: "Entered Incorrect Otp."
            })
        }
    } else {
        return res.render("auth/recruiter-change-password", {
            otpVerified: false, otpVerifiedMsg: "Otp is expired.Please Genearate New Otp."
        })
    }
    
})

app.post("/recruiter/change-password/reset-with-otp",Auth,role("recruiter"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const verified=req.session.otpVerified;
    const data=req.body;
    if(!verified){
        return res.send("Password Reset Session Is Expired.");
    }
    const user=await db.getdb().collection("users").findOne({_id:id});
    const {email}=user;
    if(data.newPassword === data.confirmPassword){
        const hash=await bcrypt.hash(data.newPassword,10);
        await db.getdb().collection("users").updateOne({_id:id},{$set:{password:hash}});
        delete req.session.otpVerified;
        return res.redirect("/recruiter/settings");
    }else{
        console.log("Password reset failed")
        return res.render("auth/recruiter-change-password",{
            confirmPass:false,confirmPassMsg:"Entered Password Doesn't Match! Re-enter password.",email:email
        });
    }
})

app.post("/recruiter/change-email/send-otp",Auth,role("recruiter"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const body=req.body;

    const data=await db.getdb().collection("users").findOne({_id:id});

    const {email,name}=data;

    const otp=Math.floor(10000 + Math.random()*90000).toString();

    const otpHash=await bcrypt.hash(otp,10);

    const expires=new Date(Date.now() + 10*60*1000);
    const option={
        from: process.env.EMAIL_USER,
        to : body.newEmail,
        subject: "CareerConnect | Email Change Verification Code",
        text: `
Hello,

We received a request to change the email associated with your CareerConnect account.

Your verification code is:

${otp}

This code will expire in 10 minutes.

For your security, please do not share this verification code with anyone. CareerConnect will never ask you to provide your OTP by email, phone, or message.

If you did not request a password reset, you can safely ignore this email. Your account will remain unchanged.

Regards,
CareerConnect Security Team
            `
    }

    const alreadyUsed = await db.getdb().collection("users").findOne({
        email: body.newEmail
    });
    
    if (alreadyUsed) {
        return res.render("auth/recruiter-settings", {
            emailDuplicate: true, msg: "Enter A New E-mail.",name:name,email:email
        })
    }
    if(email === body.newEmail) {
        return res.render("auth/recruiter-settings",{
            emailDuplicate:true , msg:"Enter A New E-mail.",name:name,email:email
        })
    }else{
        try {
            req.session.verifyOtp = false;
            await db.getdb().collection("otps").deleteMany({ email: email });
            await db.getdb().collection("otps").insertOne({ email: email, otp: otpHash, expiryAt: expires });
            await transporter.sendMail(option);
            req.session.newEmail=body.newEmail;
            return res.render("auth/recruiter-settings",{
                sendingOtp:true,name:name,email:email
            })
        } catch (err) {
            console.log("Error in sending otp :", err);
            return res.render("auth/recruiter-settings", {
                sendingOtp: false, msg: "Failed to send otp.",name:name,email:email
            })
        }
       
    }
})

app.post("/recruiter/change-email/verify-otp",Auth,role("recruiter"),async (req,res)=>{
    const id=new ObjectId(req.session.userid);
    const verified=req.session.verifyOtp;
    const body=req.body;
    const data=await db.getdb().collection("users").findOne({_id:id});
    const {name,email}=data;
    const otpStore=await db.getdb().collection("otps").findOne({email:email});
    const newEmail=req.session.newEmail;
    if(  !otpStore || !newEmail){
        return res.render("auth/recruiter-settings",{
            otpVerified:false,msg:"Email Reset Session Is Expired.Pls generate new otp.",name:name,email:email
        })
    }

    const {otp,expiryAt}=otpStore;
    const check =await bcrypt.compare(body.otp,otp);  

    const currentTime=new Date(Date.now());

    if(currentTime < expiryAt){
        if(check){
            req.session.verifyOtp=true;
            await db.getdb().collection("users").updateOne({_id:id},{$set:{email:newEmail}});
            await db.getdb().collection("otps").deleteOne({_id:otpStore._id})
            delete req.session.newEmail;
            delete req.session.verifyOtp;
            return res.render("auth/recruiter-settings",{
                name:name,email:email
            })
        } else {
            return res.render("auth/recruiter-settings", {
                otpVerified: false, msg: "Entered Otp Is Incorrect.",name:name,email:email
            }) 
        }
    }else{
        await db.getdb().collection("otps").deleteOne({_id:otpStore._id})
        return res.render("auth/recruiter-settings",{
            otpVerified:false,msg:"Otp is expired.Generate new otp.",name:name,email:email
        })
    }

})

db.connectTOdatabase().then(()=>{
    app.listen(PORT, () => {
            console.log(`CareerConnect running at http://localhost:${PORT}`);
});
})
