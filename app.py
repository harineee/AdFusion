from init import app, db
from models import User, Sponsor, Influencer, Campaign, AdRequest, FlaggedUser, PayInfo
from flask import request, jsonify, session, redirect, url_for, flash, render_template
from datetime import datetime
from functools import wraps
from collections import Counter


#LOGIN AND DECORATORS
@app.route('/')
def landing_page():
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']

        if role not in ['sponsor', 'influencer', 'admin']:
            flash('Invalid role selected.', 'danger')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('signup'))

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        if role == 'sponsor':
            sponsor = Sponsor(id=new_user.id)
            db.session.add(sponsor)
        elif role == 'influencer':
            influencer = Influencer(id=new_user.id)
            db.session.add(influencer)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


def require_role(role):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                flash(f'Access restricted to {role}s only.', 'required_role')
                return redirect(url_for('login'))
            return func(*args, **kwargs)
        return wrapped
    return decorator

require_sponsor = require_role('sponsor')
require_influencer = require_role('influencer')
require_admin  = require_role('admin')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            flash('Login successful!', 'success')

            if user.role == 'sponsor':
                return redirect(url_for('spon_dash'))
            elif user.role == 'influencer':
                return redirect(url_for('inf_dash'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dash'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('landing_page'))

#FLAG DECORATORS 
def check_flag(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        influencer_id = session.get('user_id')
        influencer = Influencer.query.get(influencer_id)
        if influencer and influencer.flag:
            flash('Your account is flagged. You cannot perform this action.', 'danger')
            return redirect(request.referrer) 
        return f(*args, **kwargs)
    return decorated_function

#Profile Decorator
def profile_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        user = User.query.get(user_id)

        if user.role == 'sponsor':
            sponsor = Sponsor.query.get(user_id)
            if not sponsor.company_name or not sponsor.industry or not sponsor.budget:
                flash("Please complete your profile to access this page.", 'complete_profile')
                return redirect(url_for('spon_dash'))

        elif user.role == 'influencer':
            influencer = Influencer.query.get(user_id)
            if not influencer.category or not influencer.niche or not influencer.reach:
                flash("Please complete your profile to access this page.", 'complete_profile')
                return redirect(url_for('inf_dash'))
        return f(*args, **kwargs)
    return decorated_function

#DASHBOARDS
@app.route('/spon_dash')
@require_sponsor
def spon_dash():
    sponsor = Sponsor.query.join(User).filter(User.id == Sponsor.id).filter(User.id == session["user_id"]).first()
    if 'user_id' not in session or session['role'] != 'sponsor':
        return redirect(url_for('login'))
    return render_template('sponsor/spon_dash.html', sponsor=sponsor)

@app.route('/inf_dash')
@require_influencer
def inf_dash():
    influencer = Influencer.query.join(User).filter(User.id == Influencer.id).filter(User.id == session["user_id"]).first()
    if 'user_id' not in session or session['role'] != 'influencer':
        flash('You need to be an influencer to access this!', 'required_role')
        return redirect(url_for('login'))
    flagged_info = FlaggedUser.query.filter_by(user_id=influencer.id).first()
    if flagged_info:
        flash('Your account has been flagged for review.', 'influencer_flagged')
    return render_template('influence/inf_dash.html',influencer=influencer, flagged_info=flagged_info)

@app.route('/admin_dash')
@require_admin
def admin_dash():
    admin = User.query.filter(User.id==session["user_id"]).first()
    if 'user_id' not in session or session['role'] != 'admin':
        flash('You need to be an admin to access this!', 'required_role')
        return redirect(url_for('login'))
    return render_template('admin/admin_dash.html',admin=admin)

#IDK
@app.route('/clear_alert', methods=['POST'])
def clear_alert():
    session.pop('alert_type', None)
    session.pop('alert_message', None)
    return '', 204


niches = [
    'Technology',
    'Fashion',
    'Food',
    'Travel',
    'Lifestyle',
    'Fitness',
    'Gaming',
    'Education',
    'Business',
    'Entertainment'
]

#CAMPAIGN MANAGEMENT
@app.route('/manage_campaigns')
@require_sponsor
@profile_check
def manage_campaigns():
    sponsor_id = session.get('user_id')
    if not sponsor_id:
        return redirect(url_for('login'))  

    today = db.func.date('now')
    ongoing_campaigns = Campaign.query.filter(Campaign.end_date >= today, Campaign.flag != True, Campaign.sponsor_id == sponsor_id).all()
    past_campaigns = Campaign.query.filter(Campaign.end_date < today, Campaign.sponsor_id == sponsor_id).all()
    flagged_campaigns = Campaign.query.filter(Campaign.flag == True, Campaign.end_date >= today, Campaign.sponsor_id == sponsor_id).all()
    ongoing_campaigns_with_counts = []
    for campaign in ongoing_campaigns:
        ad_request_count = AdRequest.query.filter_by(campaign_id=campaign.id).count()
        ongoing_campaigns_with_counts.append((campaign, ad_request_count))

    return render_template(
        'sponsor/manage_campaigns.html',
        niches=niches,
        flagged_campaigns=flagged_campaigns,
        ongoing_campaigns=ongoing_campaigns_with_counts,
        past_campaigns=past_campaigns
    )

@app.route('/create_campaign', methods=['POST'])
@require_sponsor
@profile_check
def create_campaign():
    name = request.form['name']
    description = request.form['description']
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    budget = request.form['budget']
    visibility = request.form['visibility']
    niche=request.form['niche']
    goals = request.form['goals']
    start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    new_campaign = Campaign(
        name=name,
        description=description,
        start_date=start_date,
        end_date=end_date,
        budget=budget,
        visibility=visibility,
        goals=goals,
        niche=niche,
        sponsor_id=session.get('user_id')
    )
    db.session.add(new_campaign)
    db.session.commit()

    return redirect(url_for('manage_campaigns'))

@app.route('/delete_campaign/<int:campaign_id>', methods=['GET'])
@require_sponsor
@profile_check
def delete_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign:
        try:
            db.session.delete(campaign)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting campaign: {str(e)}', 'danger')
    else:
        flash('Campaign not found.', 'warning')
    return redirect(url_for('manage_campaigns'))

@app.route('/edit_campaign/<int:campaign_id>', methods=['GET', 'POST'])
@require_sponsor
@profile_check
def edit_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)

    if request.method == 'POST':
        campaign.name = request.form['name']
        campaign.description = request.form['description']
        campaign.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        campaign.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        campaign.budget = float(request.form['budget'])
        campaign.visibility = request.form['visibility']
        campaign.goals = request.form['goals']
        campaign.niche = request.form['niche']
        try:
            db.session.commit()
            flash('Campaign updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating campaign: {str(e)}', 'danger')
        
        return redirect(url_for('manage_campaigns'))

    return render_template('sponsor/edit_campaign.html', niches=niches, campaign=campaign)

#INFLUENCER SEARCH
@app.route('/influencers', methods=['GET'])
@require_sponsor
@profile_check
def list_influencers():
    sort_by = request.args.get('sort_by', 'desc')
    selected_niche = request.args.get('niche', 'all')
    search_term = request.args.get('search', '')

    query = Influencer.query.filter(Influencer.flag != True)

    if selected_niche != 'all':
        query = query.filter_by(niche=selected_niche)

    if search_term:
        query = query.filter((User.username.ilike(f'%{search_term}%')) |(Influencer.category.ilike(f'%{search_term}%')) | (Influencer.niche.ilike(f'%{search_term}%')))

    if sort_by == 'asc':
        influencers = query.order_by(Influencer.reach.asc()).all()
    else:
        influencers = query.order_by(Influencer.reach.desc()).all()

    return render_template(
        'sponsor/inf_list.html', influencers=influencers, sort_by=sort_by, selected_niche=selected_niche,niches=niches, search_term=search_term)


@app.route('/request_ad/<int:influencer_id>', methods=['GET', 'POST'])
@require_sponsor
@profile_check
def request_ad(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)
    sender_id = session['user_id']
    receiver_id = influencer.id

    # Fetch campaigns that are not flagged, not expired, and don't have an accepted ad request from this influencer
    campaigns = Campaign.query.filter(
        Campaign.sponsor_id == sender_id,
        Campaign.flag != True,
        Campaign.end_date >= datetime.now()
    ).outerjoin(AdRequest, db.and_(
        AdRequest.campaign_id == Campaign.id,
        AdRequest.influencer_id == influencer_id,
        AdRequest.status == 'accepted'
    )).filter(AdRequest.id == None).all()

    if request.method == 'POST':
        campaign_id = request.form['campaign_id']
        messages = request.form['messages']
        requirements = request.form['requirements']
        payment_amount = request.form['payment_amount']

        existing_ad_request = AdRequest.query.filter_by(influencer_id=influencer_id, campaign_id=campaign_id).first()
        if existing_ad_request:
            flash('An ad request for this campaign and influencer already exists.', 'danger')
            return redirect(url_for('request_ad', influencer_id=influencer_id))

        new_ad_request = AdRequest(
            campaign_id=campaign_id,
            influencer_id=influencer.id,
            sender_id=sender_id,
            receiver_id=receiver_id,
            messages=messages,
            requirements=requirements,
            payment_amount=payment_amount,
            status='pending'
        )

        db.session.add(new_ad_request)
        db.session.commit()
        flash('Ad request created successfully!', 'success')
        return redirect(url_for('list_influencers'))

    return render_template('sponsor/reqbysponsor.html', influencer=influencer, campaigns=campaigns)


#CAMPAIGN SEARCH
@app.route('/list_campaign', methods=['GET'])
@require_influencer
@profile_check
@check_flag
def list_campaign():
    sort_by = request.args.get('sort_by', 'desc')
    selected_niche = request.args.get('niche', 'all')
    search_term = request.args.get('search_term', '')

    # Determine the sort order
    if sort_by == 'asc':
        sort_order = Campaign.budget.asc()
    else:
        sort_order = Campaign.budget.desc()

    # Start building the query
    query = Campaign.query.filter_by(visibility='public').filter(
        Campaign.flag != True, 
        Campaign.end_date >= datetime.now()
    )

    # Filter by niche if selected
    if selected_niche != 'all':
        query = query.filter_by(niche=selected_niche)
    
    # Filter by search term if provided
    if search_term:
        query = query.filter(
            Campaign.name.ilike(f'%{search_term}%') |
            Campaign.description.ilike(f'%{search_term}%') |
            Campaign.goals.ilike(f'%{search_term}%')
        )

    # Filter out campaigns that have been accepted by any influencer
    from sqlalchemy.orm import aliased
    from sqlalchemy import and_
    
    AdRequestAlias = aliased(AdRequest)
    
    query = query.outerjoin(
        AdRequestAlias, and_(
            AdRequestAlias.campaign_id == Campaign.id,
            AdRequestAlias.status == 'accepted'
        )
    ).filter(
        AdRequestAlias.id == None  # Ensure no accepted ad requests are associated
    )

    # Order the campaigns
    campaign = query.order_by(sort_order).all()

    return render_template('influence/camp_list.html', campaign=campaign, sort_by=sort_by, selected_niche=selected_niche, niches=niches, search_term=search_term)



@app.route('/adrequest/<int:campaign_id>', methods=['GET', 'POST'])
@require_influencer
@check_flag
@profile_check
def adrequest(campaign_id):
    current_user_id = session.get('user_id')
    influencer = Influencer.query.get_or_404(current_user_id)
    campaign = Campaign.query.get_or_404(campaign_id)
    
    if request.method == 'POST':
        messages = request.form['messages']
        requirements = request.form['requirements']
        payment_amount = float(request.form['payment_amount'])
        
        existing_request = AdRequest.query.filter_by(
        campaign_id=campaign_id, 
        influencer_id=influencer.id,
        status='accepted'
        ).first()

        if existing_request:
            flash('You have already submitted a pending request for this campaign.', 'warning')
            return redirect(url_for('list_campaign'))  
        
        ad_request = AdRequest(
            campaign_id=campaign_id,
            influencer_id=influencer.id,
            messages=messages,
            requirements=requirements,
            payment_amount=payment_amount,
            status='pending',
            sender_id=influencer.id,
            receiver_id=campaign.sponsor_id 
        )
        db.session.add(ad_request)
        db.session.commit()
        
        flash('Ad request submitted successfully!', 'success')
        return redirect(url_for('list_campaign'))  
    
    return render_template('influence/reqbyinfluence.html', campaign=campaign)

#PROFILE
@app.route('/sponsor/profile/<int:sponsor_id>', methods=['GET', 'POST'])
@require_sponsor
def sponsor_profile(sponsor_id):
    sponsor = Sponsor.query.get(sponsor_id)
    user = User.query.get(sponsor.id)
    if not sponsor:
        flash('Sponsor not found.', 'warning')
        return redirect(url_for('spon_dash'))
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        sponsor.company_name = request.form['company_name']
        sponsor.industry = request.form['industry']
        sponsor.budget = float(request.form['budget'])
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
        
        return redirect(url_for('spon_dash', sponsor_id=sponsor.id))
    return render_template('sponsor/sponsor_profile.html', sponsor=sponsor, user=user)

@app.route('/influencer/profile/<int:influencer_id>', methods=['GET', 'POST'])
@require_influencer
def influencer_profile(influencer_id):
    influencer = Influencer.query.get(influencer_id)
    user = User.query.get(influencer.id)
    if not influencer:
        flash('Influencer not found.', 'warning')
        return redirect(url_for('inf_dash'))
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        influencer.category = request.form['category']
        influencer.niche = request.form['niche']
        influencer.reach = float(request.form['reach'])
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
        
        return redirect(url_for('inf_dash', influencer_id=influencer.id))
    return render_template('influence/influencer_profile.html',niches=niches, influencer=influencer, user=user)




#SPONSOR AD REQUESTS
@app.route('/ad_requests', methods=['GET'])
@check_flag
@profile_check
def ad_requests():
    user_id = session['user_id']
    user = User.query.get_or_404(user_id)
    
    if user.role == 'sponsor':
        ad_requests = AdRequest.query.join(Campaign).outerjoin(Influencer).filter(
            ((AdRequest.sender_id == user_id) | (AdRequest.receiver_id == user_id)) &
            (Campaign.end_date >= db.func.date('now')) & (Influencer.flag == False)
        ).all()
        expired = AdRequest.query.join(Campaign).filter(Campaign.sponsor_id == user_id, Campaign.end_date < db.func.date('now')).all()
        flagged = AdRequest.query.join(Influencer, AdRequest.influencer_id == Influencer.id).join(Campaign).filter(
            Influencer.flag == True,Campaign.end_date >= db.func.date('now'),
            ((AdRequest.sender_id == user_id) | (AdRequest.receiver_id == user_id))
        ).all()
        return render_template('sponsor/sponsor_ad_requests.html', ad_requests=ad_requests, expired=expired, flagged=flagged)
    
    if user.role == 'influencer':
        ad_requests = AdRequest.query.join(Campaign).outerjoin(Influencer).filter(
            ((AdRequest.sender_id == user_id) | (AdRequest.receiver_id == user_id)) &
            (Campaign.end_date >= db.func.date('now')) &
            (Campaign.flag == False)
        ).all()
        expired = AdRequest.query.join(Campaign).filter(Campaign.end_date < db.func.date('now'),(AdRequest.sender_id == user_id) | (AdRequest.receiver_id == user_id)).all()
        flagged = AdRequest.query.join(Influencer, AdRequest.influencer_id == Influencer.id).join(Campaign).filter(
            Campaign.flag == True,
            Campaign.end_date >= db.func.date('now'),
            ((AdRequest.sender_id == user_id) | (AdRequest.receiver_id == user_id))
        ).all()
        return render_template('influence/influencer_ad_requests.html', ad_requests=ad_requests, expired=expired, flagged=flagged)

@app.route('/ad_request/modify/<int:request_id>', methods=['GET', 'POST'])
@profile_check
def modify_ad_request(request_id):
    ad_request = AdRequest.query.get_or_404(request_id)

    # Check if the current user is either the sender or receiver of the ad request
    if ad_request.sender_id != session['user_id'] and ad_request.receiver_id != session['user_id']:
        flash('You do not have permission to modify this request.', 'danger')
        return redirect(url_for('ad_requests'))

    if request.method == 'POST':
        if ad_request.status in ['accepted', 'rejected']:
            flash('Cannot modify a request that is already accepted or rejected.', 'danger')
            return redirect(url_for('ad_requests'))

        ad_request.messages = request.form.get('messages', '')
        ad_request.requirements = request.form.get('requirements', '')
        ad_request.payment_amount = float(request.form.get('payment_amount', 0.0))
        ad_request.status = 'pending'
        ad_request.latest_sender = session['user_id']  # Update latest sender

        db.session.commit()
        flash('Ad request modified successfully.', 'success')
        return redirect(url_for('ad_requests'))

    return render_template('modify_ad_request.html', ad_request=ad_request)

@app.route('/ad_request/delete/<int:request_id>', methods=['POST'])
def delete_ad_request(request_id):
    ad_request = AdRequest.query.get_or_404(request_id)
    if ad_request.sender_id != session['user_id']:
        flash('You do not have permission to delete this request.', 'danger')
        return redirect(url_for('ad_requests'))

    if ad_request.status in ['accepted', 'rejected']:
        flash('Cannot delete an accepted or rejected request.', 'danger')
        return redirect(url_for('ad_requests'))

    db.session.delete(ad_request)
    db.session.commit()
    flash('Ad request deleted successfully.', 'success')
    return redirect(url_for('ad_requests'))

@app.route('/ad_request/accept/<int:request_id>', methods=['POST'])
def accept_ad_request(request_id):
    ad_request = AdRequest.query.get_or_404(request_id)
    
    # Ensure that only the receiver can accept the request
    if session['user_id'] != ad_request.receiver_id:
        flash('You do not have permission to accept this request.', 'danger')
        return redirect(url_for('ad_requests'))
    
    ad_request.status = 'accepted'
    campaign_id = ad_request.campaign_id
    influencer_id = ad_request.influencer_id
    new_payinfo = PayInfo(
        campaign_id=campaign_id,
        influencer_id=influencer_id,
        status='pending',  
        transaction_id=None,  
        amount=ad_request.payment_amount  
    )
    db.session.add(new_payinfo)
    db.session.commit()
    flash('Ad request accepted.', 'success')
    return redirect(url_for('ad_requests'))

@app.route('/ad_request/reject/<int:request_id>', methods=['POST'])
def reject_ad_request(request_id):
    ad_request = AdRequest.query.get_or_404(request_id)
    ad_request.status = 'rejected'
    db.session.commit()
    flash('Ad request rejected.', 'success')
    return redirect(url_for('ad_requests'))

@app.route('/campaign/<int:campaign_id>/requests', methods=['GET'])
@profile_check
def view_requests(campaign_id):
    user_id = session['user_id']
    user = User.query.get_or_404(user_id)
    # Fetch the campaign based on campaign_id
    campaign = Campaign.query.get_or_404(campaign_id)
    # Ensure the user is authorized to view requests for this campaign
    if user.role == 'sponsor' and campaign.sponsor_id != user_id:
        flash('You do not have permission to view requests for this campaign.', 'danger')
        return redirect(url_for('manage_campaigns'))
    
    if user.role == 'influencer':
        ad_requests = AdRequest.query.filter_by(campaign_id=campaign_id, influencer_id=user_id).all()
    else:
        ad_requests = AdRequest.query.filter_by(campaign_id=campaign_id).all()
    
    return render_template('sponsor/view_requests.html', campaign=campaign, ad_requests=ad_requests)


########################### Admin ##########################################################
####activeuserscampaign#####
# Route to display dropdown selection between influencers and campaigns
@app.route('/view_entities', methods=['GET'])
@require_admin
def view_entities():
    view = request.args.get('view', 'influencers')
    
    if view == 'influencers':
        influencers = Influencer.query.filter(Influencer.flag != True).order_by(Influencer.reach.desc()).all()
        return render_template('admin/activeusercampaign.html', influencers=influencers, view=view)
    
    elif view == 'campaigns':
        campaigns = Campaign.query.filter(Campaign.flag != True).order_by(Campaign.budget.desc()).all()
        return render_template('admin/activeusercampaign.html', campaigns=campaigns, view=view)

# Route to flag an influencer
@app.route('/flag_influencer/<int:influencer_id>', methods=['GET'])
@require_admin
def flag_influencer(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)
    influencer.flag = True
    db.session.commit()
    flash(f'Influencer {influencer.user.username} has been flagged.', 'success')
    return redirect(url_for('view_entities', view='influencers'))

# Route to flag a campaign
@app.route('/flag_campaign/<int:campaign_id>', methods=['GET'])
@require_admin
def flag_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.flag = True
    db.session.commit()
    flash(f'Campaign {campaign.name} has been flagged.', 'success')
    return redirect(url_for('view_entities', view='campaigns'))

########flaggedusers######
@app.route('/flagged_users', methods=['GET'])
@require_admin
def flagged_users():
    search_query = request.args.get('search', '')

    if search_query:
        influencers = Influencer.query.join(User).filter(
            Influencer.flag == True,
            User.username.ilike(f'%{search_query}%')
        ).all()
    else:
        influencers = Influencer.query.filter_by(flag=True).all()

    return render_template('admin/flaggedusers.html', influencers=influencers)


@app.route('/reinstate_influencer/<int:influencer_id>', methods=['GET'])
@require_admin
def reinstate_influencer(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)
    influencer.flag = False
    db.session.commit()
    flash(f'Influencer {influencer.user.username} has been reinstated.', 'success')
    return redirect(url_for('flagged_users'))

######flaggedcampaigns#####
@app.route('/flagged_campaigns', methods=['GET'])
@require_admin  # Assuming only admins can view and reinstate flagged campaigns
def flagged_campaigns():
    search_query = request.args.get('search', '')

    if search_query:
        if search_query=='*':
            flash(f'invalid search query', 'danger')
        campaigns = Campaign.query.filter(
            Campaign.flag == True,
            
            Campaign.name.ilike(f'%{search_query}%')
        ).all()
    else:
        campaigns = Campaign.query.filter_by(flag=True).all()

    return render_template('admin/flaggedcampaigns.html', campaigns=campaigns)


@app.route('/reinstate_campaign/<int:campaign_id>', methods=['GET'])
@require_admin  # Assuming only admins can reinstate flagged campaigns
def reinstate_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.flag = False
    db.session.commit()
    flash(f'Campaign {campaign.name} has been reinstated.', 'success')
    return redirect(url_for('flagged_campaigns'))


#charts
from flask import jsonify
from collections import Counter

@app.route('/ad_chart')
def ad_request_status_data():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    # Query to get ad requests related to the current user
    ad_requests = AdRequest.query.filter(
        (AdRequest.sender_id == user_id) | (AdRequest.receiver_id == user_id)
    ).all()
    
    # Count the occurrences of each status
    status_counts = Counter(ad.status for ad in ad_requests)

    # Prepare data in the format expected by Chart.js
    data = {
        'labels': list(status_counts.keys()),
        'datasets': [{
            'label': 'Ad Request Status',
            'data': list(status_counts.values()),
            'backgroundColor': [
                'rgba(255, 99, 132, 0.2)',
                'rgba(54, 162, 235, 0.2)',
                'rgba(255, 206, 86, 0.2)',
                'rgba(75, 192, 192, 0.2)',
                'rgba(153, 102, 255, 0.2)',
                'rgba(255, 159, 64, 0.2)'
            ],
            'borderColor': [
                'rgba(255, 99, 132, 1)',
                'rgba(54, 162, 235, 1)',
                'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)',
                'rgba(153, 102, 255, 1)',
                'rgba(255, 159, 64, 1)'
            ],
            'borderWidth': 1
        }]
    }
    
    return jsonify(data)

#Payment
@app.route('/sponsor/payments')
@profile_check
@require_sponsor
def sponsor_payments():
    user_id = session['user_id']
    payments = PayInfo.query.filter_by(campaign_id=Campaign.id).filter(Campaign.sponsor_id == user_id).all()
    return render_template('sponsor/spon_pay.html', payments=payments)

@app.route('/influencer/payments')
@profile_check
@require_influencer
def influencer_payments():
    user_id = session['user_id']
    received_payments = PayInfo.query.filter_by(influencer_id=user_id, status='Paid').all()
    pending_payments = PayInfo.query.filter_by(influencer_id=user_id, status='pending').all()
    return render_template('influence/inf_pay.html', received_payments=received_payments, pending_payments=pending_payments)


import stripe

app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_51PlrDlRo11B6ZWxWKfcSilV3Bbm5xnCW30k6GiY2UHNJ1FmjJEfZCM1JNLZl8QjtBxctVejTToFSucilemanPiy300lYtCMTok'
app.config['STRIPE_SECRET_KEY'] = 'sk_test_51PlrDlRo11B6ZWxWs7FBgCqpFy8rABXBL4SwZO22NqVHATOIL6t9Tt0gzFcKOEDXEiwhugGkg9LCWmbbgdjLB3xw00CfuDh98K'
stripe.api_key = app.config['STRIPE_SECRET_KEY']

@app.route('/pay_payment/<int:payment_id>', methods=['GET', 'POST'])
@profile_check
@require_sponsor
def pay_payment(payment_id):

    pay_info = PayInfo.query.get_or_404(payment_id)
    
    if pay_info.status == 'Paid':
        flash('Payment already completed.', 'info')
        return redirect(url_for('sponsor_payments'))
    
    campaign = Campaign.query.filter_by(id=pay_info.campaign_id).first()
    influencer = Influencer.query.filter_by(id=pay_info.influencer_id).first()
    
    sponsor_user = campaign.sponsor.user  # Access the user associated with the sponsor
    
    if request.method == 'POST':
        try:
            amount = int(pay_info.amount * 100)  # Convert amount to cents
            
            if amount > 99999999:  # Check if the amount exceeds the Stripe limit
                raise ValueError("The payment amount exceeds the Stripe maximum limit.")
            
            # Create a payment intent with Stripe
            intent = stripe.PaymentIntent.create(
                amount=amount,  
                currency='usd',
                description=f'Payment for campaign {campaign.name} to influencer {influencer.user.username}',
                metadata={
                    'sponsor': sponsor_user.username,
                    'influencer': influencer.user.username,
                    'campaign': campaign.name,
                }
            )
            
            # Create a customer in Stripe
            customer = stripe.Customer.create(
                email=influencer.user.email,
                name=influencer.user.username,
                metadata={
                    'sponsor': sponsor_user.username,
                    'influencer': influencer.user.username,
                    'campaign': campaign.name,
                }
            )
            
            # Update payment info in the database
            pay_info.transaction_id = intent.id
            pay_info.status = 'Paid'
            db.session.commit()
            
            flash('Payment successful!', 'success')
            return redirect(url_for('payment_success'))  # Redirect to a success page
            
        except stripe.error.CardError as e:
            flash('Card error occurred.', 'danger')
            return render_template('payment/fail.html', error=e)
        except ValueError as ve:
            flash(str(ve), 'error')
            return redirect(url_for('pay_payment', payment_id=payment_id))
    
    # If method is GET or there's an issue, render the payment page
    return render_template('payment/paycard.html', pay_info=pay_info)

@app.route('/payment_success')
@profile_check
@require_sponsor
def payment_success():
    return render_template('payment/succ.html')

@app.route('/payment_failed')
@profile_check
@require_sponsor
def payment_failed():
    return render_template('payment/fail.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)
