from abc import ABC
from typing import List

from minerva.classifier.models import ClassificationResult
from minerva.core.models import Discussion, Message, Hashtag


class AbstractClassifier(ABC):
    def classify(self, message: Message) -> List[ClassificationResult]:
        """
        return:
            Discussion instance - nullable if none found
            Confidence level - default value is 1. Confidence level of the returned classification
            Confidence level is a scale of 0 to 1, when 1 is the highest value.
        """
        raise NotImplemented


class HashtagClassifier(AbstractClassifier):
    def classify(self, message):

        # relevant for future implementation - when the classifier will return ranging confidence levels -
        # append only if confidence level > minimal_confidence_level_to_append
        minimal_confidence_level_to_append = 0.5

        message_hashtags = message.hashtags.all().values_list("content", flat=True)
        related_discussions = Discussion.objects.filter(first_message__chat_group=message.chat_group,
                                                        hashtag__content__in=message_hashtags)
        related_discussions = related_discussions.select_related("hashtag")

        existing_hashtags = related_discussions.values_list("hashtag__content", flat=True)

        classified_discussions = []

        for hashtag in message_hashtags:
            if hashtag in existing_hashtags:
                discussion = related_discussions.filter(hashtag__content=hashtag).first()
                classified_discussions.append(ClassificationResult(discussion, 1, False))
            else:
                new_hashtag, _ = Hashtag.objects.get_or_create(content=hashtag)
                new_discussion = Discussion(first_message=message, hashtag=new_hashtag)
                classified_discussions.append(ClassificationResult(new_discussion, 1, True))

        return classified_discussions


class ReplyClassifier(AbstractClassifier):
    def classify(self, message):
        if not message.reply_to:
            return []
        parent_message = message.reply_to

        parent_discussions = parent_message.discussions.all()
        parent_discussions_count = parent_discussions.count()

        classified_discussions = []

        if parent_discussions_count == 1:
            return [ClassificationResult(parent_discussions.first(), 1, False)]
        else:
            for discussion in parent_discussions:
                classified_discussions.append(ClassificationResult(discussion, 0.5, False))

        return classified_discussions


CLASSIFIERS = (
    HashtagClassifier(),
    ReplyClassifier(),
)
