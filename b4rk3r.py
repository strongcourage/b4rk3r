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


# Get a user's ID after login sucessfully
def get_user_id(s, username):
    url_edit_profile = f"{url}/profile/{username}/edit"
    r = s.get(url_edit_profile)
    return re.search('<form\sclass="needs-validation".+action="([^"]+)', 
                r.content.decode('utf-8')).groups()[0].split('/')[-1]


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


# Pretty print the POST request
def pretty_print_POST(req):
    print('{}\n{}\r\n{}\r\n\r\n{}'.format(
        '-----------START-----------',
        req.method +
        ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))


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

    ### WIP: still failed to upgrade normal users to privileged ones?
    url_edit_profile = f"{url}/profile/{username}/edit"
    user_id = get_user_id(s, username)
    print(f"ID of user `{username}` is {user_id}")

    url_profile_update = f"{url}/profile/update/{user_id}"
    print(url_profile_update)
    params = {'creator': 1}
    profile_name = username + '_name'
    profile_description = username + '_desc'


    #r = s.post(url_profile_update, files=update_files, params=params)
    #s = requests.Session()
    #s.headers.update({'Referer': url_edit_profile})
    #r.connection.close()
    
    #s = requests.Session() 
    csrf_token = get_csrf_token(s)

    cookies = s.cookies.get_dict()
    cookie_str = "; ".join([str(x)+"="+str(y) for x,y in cookies.items()])


    update_files = {
        '_method':'PATCH',
        '_token':(None,csrf_token),
        'profile_image':('','','application/octet-stream'),
        'profile_name':(None,profile_name),
        'profile_description':(None,profile_description),
        'country':('')
    }

    burp0_url = "https://97b067f97b72-strongcourage.a.barker-social.com:443/profile/update/60"
    #burp0_cookies = {"XSRF-TOKEN": "eyJpdiI6InRGY1B0QzZoVFRDeWo2NG01MXg1bWc9PSIsInZhbHVlIjoiemt5SzBPeWx1TnIxbHBacTNSRzVBeVdiZW1ERWE5b2tDdXROY1ErZkxQWmpQR2ZpNHN6a1NIOTRGUk53ajBhQVROa2tFU0w4WmFaZ0FRZHdJOFVNZUxKY2lNdWg0QlRjWkpcL3EwVGN3K0JSY0VXZ0NsdHF3VVY3ZXp1S1pNdUVmIiwibWFjIjoiZDVhMmIwZGNlNmFjNDE1NGM3ZGI5NjQ4OWM4OGYxNWRhNjg3ZTI4ZWRlZGI1ZTZmZjMxYTViYmJhODY1ZDkwNCJ9", "barker_session": "eyJpdiI6IlpxU3IyeUZOQnNOVit3cEpEcUpybEE9PSIsInZhbHVlIjoiNTV2OUUwTFVTOW0zZWh6RXRYY3NTc2tNVGpZOXQ5N3greXdMOUgrRFhwM1FhMjJzVVRqSitCQmhcLzRCZE81ajJ4NG1FcmdRanp0cGZ0UVUzaVpmcCtxUE95Vks4QXY5bHkzYWhxWWUzUmpURFE3QWlXc2s2aEhkbTNjM2FPNGg3IiwibWFjIjoiZjlmZWY0OWE5Y2JiNWQ1MjU3ODM0YzQwNDY0N2E3NTY3OWU1NGM3NzE2MjUyMWEyNjNjNDQ0NjhhYmIzNTVhMSJ9"}
    #burp0_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data;", "Origin": "https://97b067f97b72-strongcourage.a.barker-social.com", "Referer": "https://97b067f97b72-strongcourage.a.barker-social.com/profile/user10/edit", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?1", "Te": "trailers", "Connection": "close"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Origin": "https://97b067f97b72-strongcourage.a.barker-social.com", "Referer": "https://97b067f97b72-strongcourage.a.barker-social.com/profile/user10/edit"}
    burp0_data = "-----------------------------157120647841407860791595716232\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nPATCH\r\n-----------------------------157120647841407860791595716232\r\nContent-Disposition: form-data; name=\"_token\"\r\n\r\niQkLzG0AU2h2EPQ8a4LTZy44xnvifiovocUvyNlh\r\n-----------------------------157120647841407860791595716232\r\nContent-Disposition: form-data; name=\"profile_image\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------157120647841407860791595716232\r\nContent-Disposition: form-data; name=\"profile_name\"\r\n\r\nuser1_name\r\n-----------------------------157120647841407860791595716232\r\nContent-Disposition: form-data; name=\"profile_description\"\r\n\r\nuser1_desc\r\n-----------------------------157120647841407860791595716232\r\nContent-Disposition: form-data; name=\"country\"\r\n\r\n\r\n-----------------------------157120647841407860791595716232--\r\n"
    r = s.post(burp0_url, data=update_files, headers=burp0_headers, cookies=cookies, allow_redirects=True, params=params)

    #r = requests.put(burp0_url, cookies=cookies, data=burp0_data, params=params, allow_redirects=True)
    print(r.status_code)

    #r = s.post(url_profile_update, files=update_files, params=params, headers=headers)
    #pretty_print_POST(r.request)
    #print(r.request.url)
    #print(r.request.body)
    #print(r.request.headers)

    #prepared = r.prepare()
    #pretty_print_POST(prepared)


    if r.status_code == 200:
        print(f"Update successfully user {username} to a creator")
    else:
        print("Failed to update the user's profile", r.status_code)
    
    r = s.get(url_creator_dashboard, cookies=cookies)
    print('Access to the creator dashboard', r.status_code)
    print(r.content)
    ###
    

def main():
    # Add different types of users
    add_users(users, domain_user, 0)
    add_users(premium_users, domain_user, 1)
    add_users(staffs, domain_priv, 0)
    add_users(admin, domain_priv, 1)

    # Test login function
    username = "user10"
    email = "user10@barker.com"
    #login_as_user(username, email, password)

if __name__ == "__main__":
    main()
