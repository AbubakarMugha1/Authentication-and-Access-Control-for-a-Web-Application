from fastapi import FastAPI, Request, Form, HTTPException, Cookie, Depends, status
from fastapi.middleware.cors import CORSMiddleware 
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

import datetime
import os
import oracledb
import requests
import uvicorn
import jwt
import json

import uuid
import redis 
from util import get_bill_data

# for implementing Access Control
from access_ctrl import AccessController

# Oracle client libraries for thick mode
ORACLE_HOME = os.environ.get("ORACLE_HOME")               # Defined by the file `oic_setup.sh`.
oracledb.init_oracle_client(lib_dir=ORACLE_HOME)          # Thick mode


# These environment variables come from `env.sh` file.
user_name = os.environ.get("DB_USERNAME")
user_pswd = os.environ.get("DB_PASSWORD")
db_alias  = os.environ.get("DB_ALIAS")

# OAuth config
OAUTH_REDIRECT_ENDPOINT = "callback"
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = os.environ.get("ALGORITHM")

# OAuth client config. Note that these are the secrets and the ids registered with the OAuth server.
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
CLIENT_ID = os.environ.get("CLIENT_ID")

# session cookie config
SESSION_COOKIE_NAME = "session_token"
SESSION_DURATION = datetime.timedelta(seconds = 15)

# will be used for communication
AUTH_SERVER_IP = os.environ.get("AUTH_SERVER_IP")
HOST_IP = os.environ.get("HOST_IP")

# make sure to setup connection with the DATABASE SERVER FIRST. refer to python-oracledb documentation for more details on how to connect, and run sql queries and PL/SQL procedures.
connection = oracledb.connect(user=user_name, password=user_pswd, dsn=db_alias)

#initiate redis instance
redis_db = redis.StrictRedis(host = 'localhost', port = 6379, db = 0, decode_responses = True)
# App server config
app = FastAPI()
origins = ['*']
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
) 
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Access Control setup
access_ctrl = AccessController("access.cfg")

# -----------------------------
# -----------------------------

SESSIONS = {}
# API Endpoints
# -----------------------------
# -----------------------------

# All the API endpoints are defined below

# -----------------------------------------------
# ---------- GET methods for the pages ----------
# -----------------------------------------------

# These endpoints are accessible to all users, irrespective of their roles and the authentication status.
@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    return templates.TemplateResponse("index.html",
                                        {
                                            "request": request,
                                            "auth_server": AUTH_SERVER_IP,
                                            "client_id": CLIENT_ID,
                                            "redirect_uri": f"https://{HOST_IP}/{OAUTH_REDIRECT_ENDPOINT}"
                                        })

def get_role(username):
    if username.endswith("_u1"):
        return "customer"
    if username.endswith("_u2"):
        return "bank_cashier"
    if username.endswith("_u3"):
        return "disco_employee"

async def validate_session(session_token: str | None = Cookie(default=None)):
    if not session_token:
        raise HTTPException(status_code = 401, detail = "Not authenticated. Session token missing")
    
    session_payload = redis_db.get(session_token)
    if not session_payload:
        raise HTTPException(status_code = 401, detail = "Token has expired")

    session_payload = json.loads(session_payload)
    username = session_payload["username"]
    
    if not username:
        raise HTTPException(status_code = 401, detail = "Username missing in session token")
    
    role = get_role(username)
    
    return {"username": username, "role": role}

@app.post("/callback")
async def getAccessToken(request: Request, code: str | None = None):
    if not code:
        raise HTTPException(status_code = 400, detail = "Authorization code not provided/missing.")
    
    token_url = f"https://{AUTH_SERVER_IP}/token"
    token_data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code"
    }

    try:
        response = requests.post(token_url, data = token_data, verify = False)
        response.raise_for_status()
        token_info = response.json()
        jwt_token = token_info.get("token")
        if not jwt_token:
            raise HTTPException(status_code = 401, detail = "Failed to retrieve token.")
        
        decoded_token = jwt.decode(jwt_token, SECRET_KEY, algorithms = [ALGORITHM])
        username = decoded_token.get("sub")
        if not username:
            raise HTTPException(status_code = 401, detail = "Invalid Token: Missing Username")
        

        session_id = str(uuid.uuid4())

        session_payload = {
            "username": username,
            "role": None,
        }

        redis_db.setex(session_id, 15, json.dumps(session_payload))
    
        redirect_response = RedirectResponse(url = "/dashboard", status_code = 302)
        redirect_response.set_cookie(
            key = SESSION_COOKIE_NAME,
            value = session_id,
            httponly = True,
            max_age = SESSION_DURATION.total_seconds(),
            samesite = "none",
            secure = True
        )
        return redirect_response

    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code = 500, detail = f"Error fetching token: {str(e)}")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code = 401, detail = "Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code = 401, detail = "Invalid Token")


#redirect to welcome page in case of expired token
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and exc.detail == "Token has expired":
        return RedirectResponse(url = "https://168.138.178.200", status_code = 302)

    return JSONResponse(status_code = exc.status_code, content = {"detail": exc.detail})

#manual signout endpoint which clears cookie and deletes token
@app.get("/sign-out")
async def sign_out(request: Request, session_token: str | None = Cookie(default = None)):
    # Remove the token from the SESSIONS dictionary if it exists.

    if session_token:
        redis_db.delete(session_token)

    response = RedirectResponse(url = "https://168.138.178.200", status_code = 302)
    
    response.delete_cookie(key = SESSION_COOKIE_NAME)
    
    return response

# TODO: PROTECT ALL THE RESOURCES BELOW THIS LINE WITH THE validate_session DEPENDENCY
# dashboard is accessible to all authenticated users. we dont need to however change dashboard according to the user role, as it is a generic page.
@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request, user: dict = Depends(validate_session)):
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

# TODO: Implement the access control logic for all the endpoints below

# Bill payment page
@app.get("/bill-payment", response_class=HTMLResponse)
async def get_bill_payment(request: Request, user: dict = Depends(validate_session)):
    function = "/bill-payment"
    if not access_ctrl.is_allowed(user["role"], function):
        raise HTTPException(status_code = 403, detail = "Forbidden")
    return templates.TemplateResponse("bill_payment.html", {"request": request, "user": user})

# Bill generation page
@app.get("/bill-retrieval", response_class=HTMLResponse)
async def get_bill_retrieval(request: Request, user: dict = Depends(validate_session)):
    function = "/bill-retrieval"
    if not access_ctrl.is_allowed(user["role"], function):
        raise HTTPException(status_code = 403, detail = "Forbidden")
    return templates.TemplateResponse("bill_retrieval.html", {"request": request, "user": user})

# Adjustments page
@app.get("/bill-adjustments", response_class=HTMLResponse)
async def get_bill_adjustment(request: Request, user: dict = Depends(validate_session)):
    function = "/bill-adjustment"
    if not access_ctrl.is_allowed(user["role"], function):
        raise HTTPException(status_code = 403, detail = "Forbidden")
    return templates.TemplateResponse("bill_adjustments.html", {"request": request, "user": user})

# ------------------------------------------------
# ---------- POST methods for the pages ----------
# ------------------------------------------------

# These endpoints are the ones implementing the actual business logic, and are also protected by the access control logic.

@app.post("/bill-payment", response_class=HTMLResponse)
async def post_bill_payment(request: Request, bill_id: int = Form(...), amount: float = Form(...), payment_method_id: int = Form(...)):

    # try:
    cursor = connection.cursor()

    # check if the bill exists
    bill_query = f"SELECT B.BILLID FROM BILL B WHERE B.BILLID = {bill_id}"
    cursor.execute(bill_query)
    bill_row = cursor.fetchone()

    if not bill_row:
        return templates.TemplateResponse(request=request, name="error.html", context={"error_msg": "Invalid BillID provided."})
    
    payment_date = datetime.datetime.now()

    # This function processes the payment in the database. It returns 1 if the payment is successful, and 0 otherwise. (currently no support for error codds)
    status = cursor.callfunc("fun_process_Payment", int, [bill_id, payment_date, payment_method_id, amount])

    if status != 1:
        return templates.TemplateResponse(request=request, name="error.html", context={"error_msg": "An error occured while processing the request. Please try again. Make sure the values are correct"})
    
    # find the payment status and the outstanding amount
    paymentstatus_query = f"SELECT PD.PaymentStatus FROM PAYMENTDETAILS PD WHERE PD.BILLID = {bill_id}"
    cursor.execute(paymentstatus_query)
    paymentstatus = cursor.fetchone()[0]

    pd_description = cursor.execute(f"SELECT PaymentMethodDescription FROM PaymentMethods WHERE PaymentMethodID = {payment_method_id}").fetchone()[0]

    payment_details = {
        "bill_id": bill_id,
        "amount": amount,
        "payment_method_id": payment_method_id,
        "payment_method_description": pd_description,
        "payment_date": payment_date,
        "payment_status": paymentstatus
    }

    return templates.TemplateResponse("payment_receipt.html", {"request": request, "payment_details": payment_details})

@app.post("/bill-retrieval", response_class=HTMLResponse)
async def post_bill_retrieval(request: Request, customer_id: str = Form(...), connection_id: str = Form(...), month: str = Form(...), year: str = Form(...)):

    try:
        customer_data, connections_data, bill_data, tariffs_data1, tariffs_data2, tariffs_data3, taxes_data, subsidy_data, ff_data, bills_prev_data = get_bill_data(connection, customer_id, connection_id, month, year)

        bill_details = {
            "customer_id": customer_id,
            "connection_id": connection_id,
            "customer_name": f"{customer_data[0]} {customer_data[1]}",
            "customer_address": customer_data[2],
            "customer_phone": customer_data[3],
            "customer_email": customer_data[4],
            "connection_type": connections_data[0],
            "division": connections_data[1],
            "subdivision": connections_data[2],
            "installation_date": connections_data[3].strftime("%Y-%m-%d"),
            "meter_type": connections_data[4],
            "issue_date": bill_data[0].strftime("%Y-%m-%d"),
            "net_peak_units": bill_data[1],
            "net_off_peak_units": bill_data[2],
            "bill_amount": bill_data[7],
            "due_date": bill_data[6].strftime("%Y-%m-%d"),
            "amount_after_due_date": bill_data[8],
            "month": month,
            "arrears_amount": bill_data[5],
            "fixed_fee_amount": bill_data[4],
            "tax_amount": bill_data[3],
            # all the applicable tariffs
            "tariffs": [
                {"name": tariffs_data2[0], "units": tariffs_data1[0], "rate": tariffs_data2[1], "amount": tariffs_data1[2]},
                {"name": f"{tariffs_data3[0]} (Off Peak)", "units": tariffs_data1[1], "rate": tariffs_data3[1], "amount": tariffs_data1[3]},
            ],
            # applicable taxes
            "taxes": [
                {"name": row[0], "rate": row[1], "amount": row[1]*bill_data[7]}
                for row in taxes_data
            ],
            # applicable subsidies
            "subsidies": [
                {"name": row[0], "provider_name": row[2], "rate_per_unit": row[1]}
                for row in subsidy_data
            ],
            # applicable fixed fees
            "fixed_fee": [
                {"name": row[0], "amount": row[1]}
                for row in ff_data
            ],
            # the last 10 (or lesser) bills of the customer
            "bills_prev": [
                {"month": f"{row[1]}-{row[0]}", "amount": row[2], "due_date": row[3].strftime("%Y-%m-%d"), "status": row[4]}
                for row in bills_prev_data
            ]
        }
        
        return templates.TemplateResponse("bill_details.html", {"request": request, "bill_details": bill_details})
    
    except Exception as e:
        return templates.TemplateResponse(request=request, name="error.html", context={"error_msg": f"An error occured processing the request: {str(e)}"})

# Code for handling adjustments goes here
@app.post("/bill-adjustments", response_class=HTMLResponse)
async def post_bill_adjustments(
    request: Request,
    bill_id: int = Form(...),
    officer_name: str = Form(...),
    officer_designation: str = Form(...),
    original_bill_amount: float = Form(...),
    adjustment_amount: float = Form(...),
    adjustment_reason: str = Form(...)
):
    cursor = connection.cursor()

    # check if the bill exists
    bill_query = f"SELECT B.BILLID, B.TotalAmount_BeforeDueDate FROM BILL B WHERE B.BILLID = {bill_id}"
    cursor.execute(bill_query)
    bill_row = cursor.fetchone()

    if not bill_row:
        return templates.TemplateResponse(request=request, name="error.html", context={"error_msg": "Invalid BillID provided."})
    
    amount_due = bill_row[1]

    if original_bill_amount != amount_due:
        return templates.TemplateResponse(request=request, name="error.html", context={"error_msg": "The original bill amount provided does not match the actual amount due."})
    
    # check if the bill is unpaid so far
    paymentstatus_query = f"SELECT PD.PaymentStatus FROM PAYMENTDETAILS PD WHERE PD.BILLID = {bill_id}"
    cursor.execute(paymentstatus_query)
    paymentstatus = cursor.fetchone()[0]

    if paymentstatus:
        return templates.TemplateResponse(request=request, name="error.html", context={"error_msg": "The bill has already been paid. Adjustments cannot be made to a paid bill."})

    # current date as the payment date
    adjustment_DATE = datetime.datetime.now()

    # generate an adjustment id
    adjustment_id = int(str(bill_id) + str(adjustment_DATE.year) + str(adjustment_DATE.month))
    print(adjustment_id)

    result = cursor.callfunc("fun_adjust_Bill", int, [adjustment_id, bill_id, adjustment_DATE, officer_name, officer_designation, original_bill_amount, adjustment_amount, adjustment_reason])

    adjustment_details = {
        "bill_id": bill_id,
        "officer_name": officer_name,
        "officer_designation": officer_designation,
        "original_bill_amount": original_bill_amount,
        "adjustment_amount": adjustment_amount,
        "adjustment_reason": adjustment_reason,
        "adjustment_date": adjustment_DATE,
        "confirmation_number": adjustment_id
    }

    if result == 1:
        return templates.TemplateResponse("adjustment_receipt.html", {"request": request, "adjustment_details": adjustment_details})
    else:
        return templates.TemplateResponse(request=request, name="error.html", context={"error_msg": "An error occured while processing the request. Please try again. Make sure the values are correct"})

