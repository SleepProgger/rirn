import praw
from imgurpython import ImgurClient
from time import sleep, time as now, localtime, strftime
import sqlite3
import json
from os.path import isfile
from os import unlink
import sys
import imgurpython
from imgurpython.imgur.models.gallery_album import GalleryAlbum
from imgurpython.imgur.models.gallery_image import GalleryImage

DATABASE = "posts.db"
LOCK_FILE=".lock"

#
# TODO:
# - error handling
#


# A little dirty hack to redirect all output to the stdout and also in a lockfile.
# This is beter as ./ouScript > log_file because it gets flushed after every write,
# instead once at the script end.
class Simple_logging(object):
    def __init__(self, log_file):
        self.ori_fd = sys.stdout
        self.log_fd = open(log_file, "ab")
    
    def write(self, data):
        ret = self.ori_fd.write(data)
        self.log_fd.write(data)
        self.log_fd.flush()
        return ret
log = Simple_logging("log.txt")
# From now on everything written to stdout and stderr goes over our wrapper and gets logged, too
sys.stdout = log
sys.stderr = log        
        

# Creates our database and set up our table structure, if not already done.
def init_db():
    con = sqlite3.connect(DATABASE)
    # i don't care about indices here, as we can clean everything older as time x so the db should be reasonable small
    con.execute("""CREATE TABLE IF NOT EXISTS handled_posts (
        gallery_id TEXT, /* Or should this be the primary key ?*/
        timestamp INT
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS registered_user (
        userid INT /* TODO: make primary key from this !? */
    )""")
    #con.execute("DELETE FROM handled_posts;")
    return con


# Init the imgur api from our condig.
# If we don't already have an refresh key let the user create one.
def init_imgur_api(config_file):
    if isfile(config_file):
        with open(config_file, "rb") as fd:
            config = json.load(fd)
    else: config = {}
    if "client_id" not in config: config['client_id'] = raw_input("Please insert the client id: ")
    if "client_secret" not in config: config['client_secret'] = raw_input("Please insert the client secret: ")
    if "refresh_token" not in config:
        imgurAPI = ImgurClient(config['client_id'], config['client_secret']) 
        pin = raw_input("Please visit %s and paste it here: " % imgurAPI.get_auth_url('pin'))
        credentials = imgurAPI.authorize(pin, 'pin')
        imgurAPI.set_user_auth(credentials['access_token'], credentials['refresh_token'])
        config['refresh_token'] = credentials['refresh_token']
    else:
        imgurAPI = ImgurClient(config['client_id'], config['client_secret'], refresh_token=config['refresh_token'])
    # we always recreate the config as i am lazy
    with open(config_file, "wb") as fd:
        json.dump(config, fd)
    return imgurAPI
    

# Loops over every maxElem posts on reddit frontpage and
# return (as generator) everyone linking to imgur. 
def find_imgur_frontpage_links(redditApi, maxElem=1000):
    posts = redditAPI.get_front_page(limit=maxElem)
    for i, e in enumerate(posts):
        if i % 100 == 0: print "## %i posts fetched" % i
        url = e.url.split("://", 1)[-1]
        if url.startswith("i.imgur.com") or url.startswith("imgur.com"):
            try: gid = url.rsplit("/", 1)[1].split(".", 1)[0]
            except:
                print "Invalid imgur url '%s'" % url
                continue
            yield (e, gid)



# We start here
if __name__ == '__main__':
    # Make sure this script runs only once at a time.
    if isfile(LOCK_FILE):
        print "Already running"
        sys.exit(0)
    with open(LOCK_FILE, "wb") as fd:
        fd.write(str(now())) # TODO: use pid
    
    print "Start at:", strftime(u"%a, %d %b %Y %H:%M:%S", localtime())
    # Prepare the db statements and the reddit and imgur API
    dbst_is_already_handled = "SELECT 1 FROM handled_posts WHERE gallery_id = ?;"
    dbst_insert_handled = "INSERT INTO handled_posts VALUES(?, ?);"
    dbst_is_user_registered = "SELECT 1 FROM registered_user WHERE userid = ?;"
    dbst_register_user = "INSERT INTO registered_user VALUES(?);"
    redditAPI = praw.Reddit(user_agent='rirn') # TODO add github repo url
    imgurAPI = init_imgur_api("config") 
    con = init_db()
    cur = con.cursor()
    
    # First we check if we have to register new users
    notifications = imgurAPI.get_notifications()
    nids_to_del = list()
    for message in notifications['messages']:
        if "/register" in message.content['last_message']:
            if cur.execute(dbst_is_user_registered, (message.content['with_account'],)).fetchone() is not None: continue 
            print "Register user %s with id %i" % (message.content['from'], int(message.content['with_account']))
            con.execute(dbst_register_user, (int(message.content['with_account']),))
            imgurAPI.create_message(message.content['from'], "Thank you for your registration.\nYou will receive a message every time i see one of your submissions on reddits frontpage.\nHave a nice day.")
            nids_to_del.append(str(message.id))
    if len(nids_to_del) > 0:
        # Here is a bug which leads to the notifications don't get cleaned. TODO: TODO TODO
        try: imgurAPI.mark_notifications_as_read(nids_to_del)
        except Exception as e: print "Failed to clean notis:", e
        
    # Then we loop over every reddit frontpage post linking to imgur.
    for rPost, gid in find_imgur_frontpage_links(redditAPI):
        # If we not already handled it
        if not cur.execute(dbst_is_already_handled, (gid,)).fetchone() is None: continue
        # Otherwise get the metadata from the imgur api
        try:
            d = imgurAPI.gallery_item(gid)
        except Exception as e:
            print "Can't fetch image gallery gid %s for %s (%s)" % (gid, rPost.short_link, str(e))
            cur.execute(dbst_insert_handled, (gid, now()))
            continue
        
        # Verify if the return is valid and posted to the gallery.
        if not isinstance(d, (GalleryImage, GalleryAlbum)):
            if isinstance(d, list) and isinstance(d[0], (GalleryImage, GalleryAlbum)):
                print "list return", d, "take the first one"
                d = d[0]
            else:
                print "Is no valid imgur return. no dict.", d
                continue
        # ignore anonymous submissions.
        if d.account_id is None: continue
        print "%s -> %s: %s, %s (%s)" % (rPost.short_link, rPost.url, str(d.account_id), d.account_url, d.section)
        if cur.execute(dbst_is_user_registered, (d.account_id,)).fetchone() is not None:
            # If the user is registered send them a message.
            if d.is_album: url = "http://imgur.com/a/" + gid
            else: url = "http://imgur.com/gallery/" + gid
            print "-#-", "Report repost from", d.account_url, "at", rPost.short_link  
            imgurAPI.create_message(d.account_url,
                                    "Your submission %s reached reddits frontpage (%s).\nIf you want the precious imgur karma remove your submission from the gallery now.\Have a great day," % (
                                        url, rPost.short_link
                                    ))
        cur.execute(dbst_insert_handled, (gid, now()))
        # To give imgur some time (and don't get blocked) we wait 10 seconds.
        sleep(10)
        
    con.commit() 
    unlink(LOCK_FILE)    