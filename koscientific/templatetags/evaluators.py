from django import template

register = template.Library() 

@register.filter(name='evaluator_active_count') 
def evaluator_active_count(evaluator):
    return evaluator.filter(membership__isnull=False, status__iexact='active').count()

@register.filter(name='evaluator_all_count') 
def evaluator_all_count(evaluator):
    return evaluator.filter(membership__isnull=False).count()


@register.filter(name='non_member_evaluator_active_count') 
def non_member_evaluator_active_count(evaluator):
    return evaluator.filter(membership__isnull=True, invite__isnull=False, status__iexact='active').count()

@register.filter(name='non_member_evaluator_all_count') 
def non_member_evaluator_all_count(evaluator):
    return evaluator.filter(membership__isnull=True, invite__isnull=False).count()


@register.filter(name='total_evaluator') 
def total_evaluator(evaluator):
    return evaluator.count()


@register.filter(name='total_active_evaluator') 
def total_active_evaluator(evaluator):
    return evaluator.filter(status__iexact='active').count()