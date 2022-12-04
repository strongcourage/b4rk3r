import requests,sys,re,urllib.parse

# Default password and pin for all created accounts
password = 'barker123'
pin = '12345678'

# Add multiple normal users for testing IDOR, ...
users = ['user1','user2','user3']
# Staff must be registered with the email domain "barker-social.com"
staffs = ['staff1','staff2']
# Premium users who can view who liked posts
premium_users = ['premium1','premium2']
# Creators who can view the creator's dashboard
creators = ['creator1','creator2']
# App's moderators who can view the admin's dashboard
app_mods = ['appmod1','appmod2']
rootadmins = ['rootadmin1','rootadmin2']

# Admin's username must be "admin"
admin = ['admin']

# Domain email of normal/privileged users
domain_user = "barker.com"
domain_priv = "barker-social.com"

url = sys.argv[1]
url_login = f"{url}/login"
url_register = f"{url}/register"
url_creator_dashboard = f"{url}/creator-dashboard"


# Get CSRF token of a session
def get_csrf_token(s):
    r = s.get(url)
    return re.search('<meta\sname="csrf-token".+content="([^"]+)', 
                r.content.decode('utf-8')).groups()[0]

# Automatically adding new users when starting a new testing session of Barker
def add_users(users, domain, premium_bought):
    for user in users:
        s = requests.Session()
        csrf_token = get_csrf_token(s)
        
        email = f"{user}@{domain}"
        username = user
        profile_name = user + '_name'
        profile_description = user + '_desc'

        files = {
            '_token':(None,csrf_token),
            'email':(None,email),
            'password':(None,password),
            'password_confirmation':(None,password),
            'pin':(None,pin),
            'username':(None,username),
            'profile_image':('','','application/octet-stream'),
            'profile_name':(None,profile_name),
            'profile_description':(None,profile_description),
            # set premium_bought to 1 for premium users
            'premium_bought':(None,premium_bought)
        }

        r = s.post(url_register, files=files)
        if r.status_code == 200:
            print(f"Adding user `{user}` successfully")
        else:
            print(f"Failed to add user `{user}`", r.status_code)


# Login as a user using email and password
def login_as_user(username, email, password):
    s = requests.Session()
    url_profile_edit = f"{url}/profile/{username}/edit"
    
    # Before login, failed to access the profile edit page as redirects to the login page
    r = s.get(url_profile_edit, allow_redirects=False)
    print("Failed to access the profile edit page of user `{username}`", r.status_code)
    print("Redirecting to ", r.headers['Location'])

    # Really need to close and open a new session
    r.connection.close()
    
    s = requests.Session() 
    csrf_token = get_csrf_token(s)

    files = {
        '_token':(None,csrf_token),
        'email':(None,email),
        'password':(None,password),
        'override_password':(None),
        'returnUrl':(None)
    }
    #print(files)

    r = s.post(url_login, files=files)
    if r.status_code == 200:
        print(f"Login successfully as user `{username}`")
        # After login sucessfully, we can access the profile edit page of this user
        r = s.get(url_profile_edit, allow_redirects=False)
        if r.status_code == 200:
            print("Access successfully the profile edit page of user `{username}`", r.status_code)
            #print(r.content)
    else:
        print('Failed to login as user email `{email}`', r.status_code)


def main():
    # Add different types of users
    add_users(users, domain_user, 0)
    add_users(premium_users, domain_user, 1)
    add_users(staffs, domain_priv, 0)
    add_users(admin, domain_priv, 1)

    # Test login function
    username = "user1"
    email = "user1@barker.com"
    login_as_user(username, email, password)

if __name__ == "__main__":
    main()
