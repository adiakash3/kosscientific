from rest_framework.pagination import PageNumberPagination


class MyPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 1000
    last_page_strings = ('the_end',)

    def get_next_link(self):
        if not self.page.has_next():
            return None
        page_number = self.page.next_page_number()
        return page_number

    def get_previous_link(self):
        if not self.page.has_previous():
            return None
        page_number = self.page.previous_page_number()
        return page_number

    def get_paginated_response(self, data):
        response = super(MyPagination, self).get_paginated_response(data)
        response.data["total_pages"] = self.page.paginator.num_pages
        response.data['prev'] = response.data['previous']
        del response.data['previous']
        # response.data['prev'] = self.page.previous_page_number()
        return response