import json

from django.http import JsonResponse
from rest_framework import status
from rest_framework.views import APIView

from minerva.core.models import Discussion, Message, ChatGroup
from minerva.webapp.serializers import DiscussionStatsRequestSerializer, DiscussionStatsSerializer, \
    GroupStatsRequestSerializer, GroupStatsSerializer, MessageSerializer, DiscussionSummaryRequestSerializer, \
    DiscussionMessageRequestSerializer, DiscussionSummarySerializer


class DiscussionMessagesView(APIView):
    def post(self, request):
        request_serializer = DiscussionMessageRequestSerializer(data=json.loads(request.data))
        if not request_serializer.is_valid():
            return JsonResponse(request_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user_id = request_serializer.data.get('user_id')
        discussion_id = request_serializer.data.get('discussion_id')
        user_groups = ChatGroup.objects.filter(members__id=user_id)

        messages = Message.objects.filter(chat_group__in=user_groups)
        messages = messages.filter(discussions__id=discussion_id)

        responses = (MessageSerializer.from_message(message) for message in messages)

        return JsonResponse([r.data for r in responses], status=status.HTTP_200_OK, safe=False)


class DiscussionSummaryView(APIView):
    LATEST_MESSAGE_AMOUNT = 3

    def post(self, request):
        request_serializer = DiscussionSummaryRequestSerializer(data=json.loads(request.data))
        if not request_serializer.is_valid():
            return JsonResponse(request_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user_id = request_serializer.data.get('user_id')
        filters = request_serializer.data.get('filters')
        page_num = request_serializer.data.get('page_num')

        discussions = Discussion.objects.filter(messages__chat_group__members__id=user_id)

        response = []
        for discussion in discussions:
            discussion_chat_group = discussion.first_message.chat_group
            discussion_messages = Message.objects.filter(discussions__id=discussion.id)
            message_count = discussion_messages.count()
            latest_discussion_messages = discussion_messages.order_by('-last_updated')
            last_discussion_message = latest_discussion_messages.first()
            latest_discussion_messages = latest_discussion_messages[:self.LATEST_MESSAGE_AMOUNT]
            last_updated = None
            if last_discussion_message:
                last_updated = last_discussion_message.last_updated.isoformat()

            response.append(
                DiscussionSummarySerializer({
                    "discussion_id": discussion.id,
                    "hashtag": discussion.hashtag,
                    "group_id": discussion_chat_group.id,
                    "group_name": discussion_chat_group.name,
                    "message_count": message_count,
                    "last_updated": last_updated,
                    "first_message": discussion.first_message,
                    "latest_messages": latest_discussion_messages
                })
            )

        return JsonResponse([r.data for r in response], status=status.HTTP_200_OK, safe=False)


# TODO: implement filtering by group ID
class DiscussionStatsView(APIView):
    def post(self, request):
        request_serializer = DiscussionStatsRequestSerializer(data=request.POST)
        if not request_serializer.is_valid():
            return JsonResponse(request_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user_id = request_serializer.data.get('user_id')

        discussions = Discussion.objects.filter(messages__chat_group__members__id=user_id)

        response = []
        for discussion in discussions:
            discussion_chat_group = discussion.first_message.chat_group
            discussion_messages = Message.objects.filter(discussion=discussion)
            message_count = discussion_messages.count()
            last_discussion_message = discussion_messages.order_by('-last_updated').first()
            last_updated = None
            if last_discussion_message:
                last_updated = last_discussion_message.last_updated.isoformat()

            response.append(
                DiscussionStatsSerializer({
                    "id": discussion.id,
                    "hashtag": discussion.hashtag,
                    "group_id": discussion_chat_group.id,
                    "group_name": discussion_chat_group.name,
                    "message_count": message_count,
                    "last_updated": last_updated
                })
            )

        return JsonResponse([r.data for r in response], status=status.HTTP_200_OK)


class GroupStatsView(APIView):
    def post(self, request):
        request_serializer = GroupStatsRequestSerializer(data=request.POST)
        if not request_serializer.is_valid():
            return JsonResponse(request_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user_id = request_serializer.data.get('user_id')

        groups = ChatGroup.objects.filter(members__id=user_id)

        response = []
        for group in groups:
            group_messages = Message.objects.filter(chat_group=group)
            last_group_message = group_messages.order_by('-last_updated').first()
            last_updated = None
            if last_group_message:
                last_updated = last_group_message.last_updated.isoformat()

            response.append(
                GroupStatsSerializer({
                    "id": group.id,
                    "name": group.name,
                    "last_updated": last_updated,
                    "app_name": group.application.name
                })
            )

        return JsonResponse([r.data for r in response], status=status.HTTP_200_OK, safe=False)