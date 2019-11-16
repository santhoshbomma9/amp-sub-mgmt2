import uuid
import msal
import json
from flask import (
    Flask, jsonify, redirect, render_template, request, session, url_for, flash)
from flask_session import Session
from . import amprepo, app_config, constant, utils, app
from functools import wraps
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app.config.from_object(app_config)
Session(app)
requested_url =''


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("isadmin") or session.get("isadmin") == False:
            return render_template(constant.ERROR_PAGE, user=session["user"]) 
        return f(*args, **kwargs)
    return decorated_function


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', user=session["user"]), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500


@app.route("/")
def login():
    if not session.get("user"):
        session["state"] = str(uuid.uuid4())
        auth_url = utils._build_msal_app().get_authorization_request_url(
                    [],  # openid+profile are included by default
                    state=session["state"],
                    redirect_uri=url_for("authorized", _external=True, _scheme=app_config.HTTP_SCHEME))
        return redirect(auth_url, code=302)
    else:
        global requested_url
        if requested_url:
            return redirect(requested_url)
        else:
            return redirect(url_for("dashboard"))


@app.route(app_config.REDIRECT_PATH)  # your app's redirect_uri set in AAD
def authorized():
    if request.args.get('state') == session.get("state"):
        cache = utils._load_cache()
        result = utils._build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=[],  # Misspelled scope would cause an HTTP 400 error here
            redirect_uri=url_for("authorized", _external=True, _scheme=app_config.HTTP_SCHEME))
        if "error" in result:
            return "Login failure: %s, %s" % (
                result["error"], result.get("error_description"))
        session["user"] = result.get("id_token_claims")
        session["isadmin"] = app_config.TENANT_ID in session["user"]['iss']
        utils._save_cache(cache)
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
@admin_login_required
def dashboard():
    subscriptions_root = amprepo.get_subscriptions()
    subscriptions = subscriptions_root['subscriptions']
    return render_template('index.html', user=session["user"], subscriptions=subscriptions, version=msal.__version__)


# todo delete subscription
@app.route("/edit/<subscriptionid>", methods=['GET', 'POST'])
@login_required
def edit(subscriptionid):
    subscription = amprepo.get_subscription(subscriptionid)
    plans = amprepo.get_availableplans(subscriptionid)

    if request.method == 'POST':
        selected_subscription = request.form['subscription_id']
    
        if 'activate' in request.form:
            selected_plan = request.form['subscription_plan_id']
            response = amprepo.activate_subscriptionplan(selected_subscription, selected_plan)
        elif 'update' in request.form:
            selected_plan = request.form['selectedplan']
            response = amprepo.update_subscriptionplan(selected_subscription, selected_plan)
        else:
            return redirect(url_for(constant.ERROR_PAGE))

        if response.status_code == 202 or response.status_code:
            flash(f'{response.status_code} Update successfully')
        else:
            flash(response.status_code, 'Update not successfully')
    
    filtered_dimensions_by_offer = None
    if app_config.Dimension_Data:
        dimensions = json.loads(app_config.Dimension_Data)
        filtered_dimensions_by_offer= dimensions[subscription['offerId']]
        print(filtered_dimensions_by_offer)
    
    return render_template(constant.MANAGE_SUBSCRIPTION_PAGE, user=session["user"], subscription=subscription, available_plans=plans, dimension=filtered_dimensions_by_offer)




@app.route("/operations/<subscriptionid>")
@login_required
@admin_login_required
def operations(subscriptionid):
    subname = request.args.get('subscriptionname')
    sub_operations_by_subid = amprepo.get_sub_operations(subscriptionid)
    sub_operations_by_webhook = amprepo.get_sub_operations_webhook(subscriptionid)
    sub_operations_by_isv = amprepo.get_sub_operations_isv(subscriptionid)
    return render_template(constant.SUBSCRIPTION_OPERATIONS_PAGE, user=session["user"], subsciptionname=subname, subscriptionid=subscriptionid, operations=sub_operations_by_subid, webhookops=sub_operations_by_webhook, isvops=sub_operations_by_isv)


# todo change quantity
# need to save the response
@app.route("/updateoperation/<operationid>", methods=['GET', 'POST'])
@login_required
@admin_login_required
def updateoperation(operationid):
    subid = request.args.get('subid')
    planid = request.args.get('planid')
    quantity = request.args.get('quantity')
    subsciptionname = request.args.get('subsciptionname')

    if request.method == 'POST':
        status = ''
        if 'success' in request.form:
            status = 'Success'
        elif 'failure' in request.form:
            status = 'Failure'

        response = amprepo.update_sub_operation(subid, operationid, planid, quantity, status)
        if response.status_code and response.status_code == 200:
            flash(f'{response.status_code} Patch successfull')
        else:
            flash(f'{response.text} Update not successfull')

    return render_template("suboperationmanage.html", user=session["user"], operationid=operationid,subid=subid, planid=planid, quantity=quantity, subsciptionname=subsciptionname)


@app.route("/webhook", methods=['POST'])
def webhook():

    try:
        utils._validate_jwt_token(request.headers.get('Authorization'))
        # connect to table storage
        request_payload = request.get_json(force=True)
        request_payload["PartitionKey"] = request_payload['subscriptionId']
        request_payload["RowKey"] = request_payload['id']
        utils._store_in_azure_table(app_config.WEBHOOK_OPS_STORAGE_TABLE_NAME, request_payload)
        return jsonify(), 201
    except Exception as e:
        app.logger.error(e)
        return jsonify("An exception occurred"), 500


@app.route("/landingpage", methods=['GET', 'POST'])
@login_required
def landingpage():

    if request.method == 'POST':
        selected_subscription = request.form['subscription_id']
        action = ''
        if 'activate' in request.form:
            selected_plan = request.form['subscription_plan_id']
            action = 'ACTIVATE'
        elif 'update' in request.form:
            selected_plan = request.form['selectedplan']
            action = 'UPDATE'
        
        message = Mail(
            from_email=app_config.SENDGRID_FROM_EMAIL,
            to_emails=app_config.SENDGRID_TO_EMAIL,
            subject='Sending with Twilio SendGrid is Fun',
            html_content=f'<strong>and easy {selected_subscription} {selected_plan} {action} to do anywhere, even with Python</strong>')
        try:
            sendgrid_client = SendGridAPIClient(app_config.SENDGRID_APIKEY)
            response = sendgrid_client.send(message)
            flash(f'{response.status_code} Message sent successfully')
        except Exception as e:
            flash(e.message, 'error')

    token = request.args.get('token')
    subscription = amprepo.get_subscriptionid_by_token(token)
    if not token or 'id' not in subscription:
        return render_template(constant.ERROR_PAGE, user=session["user"])  
    subscription_data = amprepo.get_subscription(subscription['id'])
    plans = amprepo.get_availableplans(subscription['id'])
    
    return render_template(constant.CUSTOMER_MANAGE_SUBSCRIPTION_PAGE, user=session["user"], subscription=subscription_data, available_plans=plans)


@app.route("/privacy")
def privacy():
    return 'This is a sample privacy policy'

@app.route("/support", methods=['GET', 'POST'])
@login_required
def support():
    if request.method == 'POST':
        replyEmail = request.form['email']
        question = request.form['message']
        
        message = Mail(
            from_email=app_config.SENDGRID_FROM_EMAIL,
            to_emails=app_config.SENDGRID_TO_EMAIL,
            subject='Sending with Twilio SendGrid is Fun',
            html_content=f'<strong>and easy {question}  {replyEmail} to do anywhere, even with Python</strong>')
        try:
            sendgrid_client = SendGridAPIClient(app_config.SENDGRID_APIKEY)
            response = sendgrid_client.send(message)
            flash(f'{response.status_code} Message sent successfully')
        except Exception as e:
            flash(e.message, 'error')
    

    return render_template('support.html', user=session["user"])


@app.route("/logout")
def logout():
    session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        #app_config.AUTHORITY + "/" + app_config.TENANT_ID + "/oauth2/v2.0/logout" +
        app_config.AUTHORITY + "/common/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("login", _external=True, _scheme=app_config.HTTP_SCHEME))


@app.before_request
def before_request_func():
    global requested_url
    if not session.get("user") and request.endpoint != 'authorized' and request.endpoint != 'login' and request.endpoint != 'webhook':
        requested_url = request.url

    if session.get("user") and request.endpoint != 'authorized' and request.endpoint != 'login' and request.endpoint != 'webhook':
        requested_url = None