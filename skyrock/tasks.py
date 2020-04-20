
from celery.task.schedules import crontab
from celery import  shared_task
from celery.utils.log import get_task_logger
import requests
import json
import os
import datetime
from config import settings


logger = get_task_logger(__name__)


@shared_task 
def send_notifiction():
    from skyrock.models import Booking
    from skyrock.enums import AttendanceStatus
    from skyrock.utils.common import send_email

    # secret = os.environ.get('AZURE_SECRET')
    # clientid = os.environ.get('AZURE_CLIENT_ID')
    # azureurl = "https://login.microsoftonline.com/3f4e8d27-2f33-495d-a6e4-2be47eb6f3ad/oauth2/v2.0/token"
    # payload = {"client_id": clientid, "client_secret": secret,"grant_type":"client_credentials","scope":"api%3A//6961b176-33ea-4857-9c11-a596501e9377/.default"}
    # print(json.dumps(payload))
    # headers = {
    #     'Content-Type': 'application/x-www-form-urlencoded'
    #     }
    # response = requests.request("POST", azureurl, headers=headers, data = json.dumps(payload))
    # print(response.text)
    
    bookings = Booking.objects.filter(attendance_status=AttendanceStatus.NONE, date = datetime.date.today())
    recipients = ['stephan@skyrockprojects.com','tony@skyrockprojects.com', 'ethan@skyrockprojects.com']
    message = []
    for booking in bookings: 
        if str(booking.session.teacher.email) not in recipients:
            recipients.append(str(booking.session.teacher.email))
        message.append( str(booking.session.teacher.first_name) + " " + str(booking.session.teacher.last_name) + ": " + str(booking.student.student_id) + " " + str(booking.student.first_name) + " " + str(booking.student.last_name) + " " + str(booking.session.description) + " " + str(booking.date))

    from django.core.mail import send_mail

    # context = {"user": booking.session.teacher.email }
    # send_mail('account/email/email_attendance',str(booking.session.teacher.email),context)
    # email_template_txt = 'email/email_attendance_message.txt'
    # message = get_template(email_template_txt).render(context)

    messageToStr='\n'.join(map(str, message))

    message = send_mail(
        "Skyrock Daily Attendance Reminder - " + str(datetime.date.today()),
        "The system has detected that the following student's attendance have not been marked: \n" + messageToStr ,
        "info@skyrockprojects.com",
        recipients,

    )

    #     except AttributeError:
    #         pass
    # print('what')
    return 'ye'



@shared_task 
def send_weekly_report():
    from skyrock.models import Booking, CampBooking, Client, Session
    from django.db.models import Count, Sum
    from skyrock.common import get_student_hours, get_client_hours, get_client_hours_penalty
    from skyrock.enums import AttendanceStatus
    from skyrock.utils.common import send_email
    from django.core.mail import send_mail

    bookings = {}
    total_services_rendered_attended = 0 
    total_services_rendered_absent = 0 
    total_hours_absent=0
    total_hours_attended=0
    average_service_rate =0
    all_clients_hours_remaining=0
    start_date=datetime.date.today()-datetime.timedelta(days=7)
    end_date=datetime.date.today()

    total_clients = Client.objects.filter().count()
    total_club_clients = Booking.objects.filter(date__range=(start_date, end_date)).values('client__identifier').distinct()
    total_club_students = Booking.objects.filter(date__range=(start_date, end_date)).values('student__identifier').distinct()
    total_club_students_attended_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="attended").values('student__identifier').distinct().count()
    total_club_students_absent_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="absent").values('student__identifier').distinct().count()
    total_club_students_absentwithcert_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="absent with cert").values('student__identifier').distinct().count()
    total_club_students_none_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="none").values('student__identifier').distinct().count()
    total_club_students_noshow_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="noshow").values('student__identifier').distinct().count()
       
    total_classes = Session.objects.filter()


    for client in Client.objects.all():
                data = Booking.objects.filter(client__identifier=client.identifier) 
                bookings['attended'] = data.filter(attendance_status="attended", date__range=(start_date, end_date)) \
                    .values('session__duration') \
                    .annotate(Sum('session__duration'))
                if len(bookings['attended']) > 0:
                     total_services_rendered_attended += bookings['attended'][0].get('session__duration__sum')*client.service_rate
                     total_hours_attended += bookings['attended'][0].get('session__duration__sum')

                bookings['absent'] = data.filter(attendance_status="absent", date__range=(start_date, end_date)) \
                    .values('session__duration') \
                    .annotate(Sum('session__duration'))
                if len(bookings['absent']) > 0:
                     total_services_rendered_absent += (bookings['absent'][0].get('session__duration__sum')/2)*client.service_rate
                     total_hours_absent += bookings['absent'][0].get('session__duration__sum')
                
                average_service_rate += client.service_rate

                all_clients_hours_remaining += get_client_hours(client)
            
    recipients = ['stephan@skyrockprojects.com','chin@skyrockprojects.com', 'chris@skyrockprojects.com','ethan@skyrockprojects.com','tony@skyrockprojects.com','simon@skyrockprojects.com']

    send_mail(
        "Skyrock Weekly Report - " + str(datetime.date.today()),
        "This is a weekly report of client and student activities related to clubs at Skyrock for the past 7 days: \n" + \
        "Clients: " + \
        "\nTotal Clients: " + str(total_clients) + \
        "\nTotal Club Clients: " + str(total_club_clients.count()) + \
        "\nAverage Service Rate: " + str(average_service_rate/total_clients) + \
        "\nTotal amount of hours remaining: " + str(all_clients_hours_remaining) + \
        "\nServices rendered [Attended] (7 days): " + str(total_services_rendered_attended) + \
        "\nServices rendered [Absent] (7 days): " + str(total_services_rendered_absent) + \
        "\nServices rendered Total (7 days): " + str(total_services_rendered_attended + total_services_rendered_absent) + \
        "\nHours [Attended] (7 days): " + str(total_hours_attended) + \
        "\nHours [Absent] (7 days): " + str(total_hours_absent) + \
        "\n\nStudents: " + \
        "\nTotal Club Students (7 days): " + str(total_club_students.count()) + \
        "\nTotal Club Students [Attended] (7 days): " + str(total_club_students_attended_range) + \
        "\nTotal Club Students [Absent] (7 days): " + str(total_club_students_absent_range) + \
        "\nTotal Club Students [Absent with Cert] (7 days): " + str(total_club_students_absentwithcert_range) + \
        "\nTotal Club Students [None] (7 days): " + str(total_club_students_none_range) + \
        "\nTotal Club Students [No Show] (7 days): " + str(total_club_students_noshow_range) + \
        "\n\nClubs: " + \
        "\nTotal Club Students: " + str(total_club_students.count()) + \
        "\nTotal Club Students [Tianmu]: " + str(total_club_students.filter(session__location='tianmu').count()) + \
        "\nTotal Club Students [Dazhi]: " + str(total_club_students.filter(session__location='dazhi').count()) + \
        "\nTotal Club Students [Daan]: " + str(total_club_students.filter(session__location='daan').count()) + \
        "\nTotal Club Students [Hsinchu]: " + str(total_club_students.filter(session__location='hsinchu').count()) + \
        "\nTotal Club Sessions: " + str(total_classes.count()) + \
        "\nTotal Club Sessions [Young Inventors]: " + str(total_classes.filter(club='Young Inventors').count()) + \
        "\nTotal Club Sessions [Machine Makers]: " + str(total_classes.filter(club='Machine Makers').count()) + \
        "\nTotal Club Sessions [Code Wizards]: " + str(total_classes.filter(club='Code Wizards').count()) + \
        "\nTotal Club Sessions [Nano]: " + str(total_classes.filter(club='Nano').count()) + \
        "\nTotal Club Sessions [Mega]: " + str(total_classes.filter(club='Mega').count())
        
        
        ,
        "info@skyrockprojects.com",
        recipients,

    )

    return 'eyhoo'

@shared_task 
def send_monthly_report():
    from skyrock.models import Booking, CampBooking, Client, Session
    from django.db.models import Count, Sum
    from skyrock.common import get_student_hours, get_client_hours, get_client_hours_penalty
    from skyrock.enums import AttendanceStatus
    from skyrock.utils.common import send_email
    from django.core.mail import send_mail

    bookings = {}
    total_services_rendered_attended = 0 
    total_services_rendered_absent = 0 
    total_hours_absent=0
    total_hours_attended=0
    average_service_rate =0
    all_clients_hours_remaining=0
    start_date=datetime.date.today()-datetime.timedelta(days=30)
    end_date=datetime.date.today()

    total_clients = Client.objects.filter().count()
    total_club_clients = Booking.objects.filter(date__range=(start_date, end_date)).values('client__identifier').distinct()
    total_club_students = Booking.objects.filter(date__range=(start_date, end_date)).values('student__identifier').distinct()
    total_club_students_attended_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="attended").values('student__identifier').distinct().count()
    total_club_students_absent_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="absent").values('student__identifier').distinct().count()
    total_club_students_absentwithcert_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="absent with cert").values('student__identifier').distinct().count()
    total_club_students_none_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="none").values('student__identifier').distinct().count()
    total_club_students_noshow_range = Booking.objects.filter(date__range=(start_date, end_date),attendance_status="noshow").values('student__identifier').distinct().count()
       
    total_classes = Session.objects.filter()


    for client in Client.objects.all():
                data = Booking.objects.filter(client__identifier=client.identifier) 
                bookings['attended'] = data.filter(attendance_status="attended", date__range=(start_date, end_date)) \
                    .values('session__duration') \
                    .annotate(Sum('session__duration'))
                if len(bookings['attended']) > 0:
                     total_services_rendered_attended += bookings['attended'][0].get('session__duration__sum')*client.service_rate
                     total_hours_attended += bookings['attended'][0].get('session__duration__sum')

                bookings['absent'] = data.filter(attendance_status="absent", date__range=(start_date, end_date)) \
                    .values('session__duration') \
                    .annotate(Sum('session__duration'))
                if len(bookings['absent']) > 0:
                     total_services_rendered_absent += (bookings['absent'][0].get('session__duration__sum')/2)*client.service_rate
                     total_hours_absent += bookings['absent'][0].get('session__duration__sum')
                
                average_service_rate += client.service_rate

                all_clients_hours_remaining += get_client_hours(client)
            
    recipients = ['stephan@skyrockprojects.com','chin@skyrockprojects.com', 'chris@skyrockprojects.com','ethan@skyrockprojects.com','tony@skyrockprojects.com','simon@skyrockprojects.com']

    send_mail(
        "Skyrock Monthly Report - " + str(datetime.date.today()),
        "This is a monthly report of client and student activities related to clubs at Skyrock for the past 30 days: \n" + \
        "Clients: " + \
        "\nTotal Clients: " + str(total_clients) + \
        "\nTotal Club Clients: " + str(total_club_clients.count()) + \
        "\nAverage Service Rate: " + str(average_service_rate/total_clients) + \
        "\nTotal amount of hours remaining: " + str(all_clients_hours_remaining) + \
        "\nServices rendered [Attended] (30 days): " + str(total_services_rendered_attended) + \
        "\nServices rendered [Absent] (30 days): " + str(total_services_rendered_absent) + \
        "\nServices rendered Total (30 days): " + str(total_services_rendered_attended + total_services_rendered_absent) + \
        "\nHours [Attended] (30 days): " + str(total_hours_attended) + \
        "\nHours [Absent] (30 days): " + str(total_hours_absent) + \
        "\n\nStudents: " + \
        "\nTotal Club Students (30 days): " + str(total_club_students.count()) + \
        "\nTotal Club Students [Attended] (30 days): " + str(total_club_students_attended_range) + \
        "\nTotal Club Students [Absent] (30 days): " + str(total_club_students_absent_range) + \
        "\nTotal Club Students [Absent with Cert] (30 days): " + str(total_club_students_absentwithcert_range) + \
        "\nTotal Club Students [None] (30 days): " + str(total_club_students_none_range) + \
        "\nTotal Club Students [No Show] (30 days): " + str(total_club_students_noshow_range) + \
        "\n\nClubs: " + \
        "\nTotal Club Students (30 days): " + str(total_club_students.count()) + \
        "\nTotal Club Students [Tianmu] (30 days): " + str(total_club_students.filter(session__location='tianmu').count()) + \
        "\nTotal Club Students [Dazhi] (30 days): " + str(total_club_students.filter(session__location='dazhi').count()) + \
        "\nTotal Club Students [Daan] (30 days): " + str(total_club_students.filter(session__location='daan').count()) + \
        "\nTotal Club Students [Hsinchu] (30 days): " + str(total_club_students.filter(session__location='hsinchu').count()) + \
        "\nTotal Club Sessions: " + str(total_classes.count()) + \
        "\nTotal Club Sessions [Young Inventors]: " + str(total_classes.filter(club='Young Inventors').count()) + \
        "\nTotal Club Sessions [Machine Makers]: " + str(total_classes.filter(club='Machine Makers').count()) + \
        "\nTotal Club Sessions [Code Wizards]: " + str(total_classes.filter(club='Code Wizards').count()) + \
        "\nTotal Club Sessions [Nano]: " + str(total_classes.filter(club='Nano').count()) + \
        "\nTotal Club Sessions [Mega]: " + str(total_classes.filter(club='Mega').count())
        
        
        ,
        "info@skyrockprojects.com",
        recipients,

    )

    return 'eyhoo'
