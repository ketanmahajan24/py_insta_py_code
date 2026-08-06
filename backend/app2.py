from instagrapi import Client

cl = Client()

cl.delay_range = [2, 5]

try:
    cl.login("samarthmahajan01", "Ketan@2408")
    print("Logged in!")
    cl.dump_settings("session.json")

except Exception as e:
    print(type(e))
    print(e)