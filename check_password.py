import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0
    #print(response.text) #gives all the hashes of the first5 that match with the website

def pwned_api_check(password):
    #check password if it exists in API response
    #print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:] #get first five and the remaining characters
    response = request_api_data(first5_char)
    #print(response)
    return get_password_leaks_count(response, tail)
    

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password')
        else:
            print(f'{password} was not found.. carry on with this!')
    return 'done!'

if __name__ == '__main__': #run only if it is the file being ran from command line, not being imported
    sys.exit(main(sys.argv[1:])) #to exit for reasons if the code doesnt exit
