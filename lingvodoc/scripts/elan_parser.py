# -*- coding: utf-8 -*-
import re
import pympi

import collections
try: from xml.etree import cElementTree as ElementTree
except ImportError: from xml.etree import ElementTree

def hyphen_to_dash(string_with_hyphen):
    if not string_with_hyphen:
        return string_with_hyphen
    restricted_symbs = ["\xad",  # Soft hyphen
                        "\xAF",  # Spacing macron
                        "\x96", # en dash
                        "\u2013",
                        "\x97", # em dash
                        "\u2014"
                        ]
    for symbol in restricted_symbs:
        string_with_hyphen = string_with_hyphen.replace(symbol, "-")
    return string_with_hyphen

class Word:
    def __init__(self, index=None, text=None, tier=None, time=None):
        self.index = index
        self.text = self.strip(text)
        self.tier = tier
        self.time = time

    def strip(self, string):
        if type(string) is str:
            return hyphen_to_dash(string.strip())
        return string

    def get_tuple(self):
        return((self.index, self.text, self.tier, self.time))

class Elan:
    def __init__(self, eaf_path):

        self.result = collections.OrderedDict()
        self.word_tier = {}
        self.tiers = []
        self.top_tiers = []
        self.tier_refs = collections.defaultdict(set)
        self.word = {}
        self.main_tier_elements = []
        self.noref_tiers = []
        self.reader = ElementTree.parse(eaf_path)
        self.xml_obj = self.reader.getroot()
        self.eafob = pympi.Elan.Eaf(eaf_path)



    def get_annotation_data_for_tier(self, id_tier):
        a = self.eafob.tiers[id_tier][0]
        return [(self.eafob.timeslots[a[b][0]], self.eafob.timeslots[a[b][1]], a[b][2])
                for b in a]

    def get_annotation_data_between_times(self, id_tier, start, end):
        tier_data = self.eafob.tiers[id_tier][0]
        anns = ((self.eafob.timeslots[tier_data[a][0]], self.eafob.timeslots[tier_data[a][1]], a)
                for a in tier_data)
        sorted_words = sorted([a for a in anns if a[0] >= start and a[1] <= end],  key=lambda time_tup: time_tup[1] )
        return [x for x in sorted_words]
        #sorted([a[2] for a in anns if a[1] >= start and a[0] <= end],  key=lambda time_tup: time_tup[0] )


    def parse(self):

        # Choosing top-level text tier as first top-level tier referring to 'literary translation' and
        # 'translation' tiers.

        for element in self.xml_obj:
            if element.tag == 'TIER':
                tier_id = element.attrib['TIER_ID']
                if 'PARENT_REF' in element.attrib:
                    tier_ref = element.attrib['PARENT_REF']
                    self.tier_refs[tier_ref].add(tier_id)
                else:
                    self.top_tiers.append(tier_id)
                self.tiers.append(tier_id)

        self.top_level_tier = None

        for tier_id in self.tier_refs:
            if self.tier_refs[tier_id].issuperset(('literary translation', 'translation')):
                self.top_level_tier = tier_id

        if self.top_level_tier is None:
            raise NotImplementedError

        for element in self.xml_obj:
            if element.tag == 'TIER':
                tier_id = element.attrib['TIER_ID']
                for elem1 in element:
                    if elem1.tag == 'ANNOTATION':
                        for elem2 in elem1:
                            self.word_tier[elem2.attrib["ANNOTATION_ID"]] = tier_id
                            if tier_id == "translation":
                                self.main_tier_elements.append(elem2.attrib["ANNOTATION_ID"])
                            self.word[elem2.attrib["ANNOTATION_ID"]] = [x for x in elem2][0].text
                            if elem2.tag == 'REF_ANNOTATION':
                                annot_ref = elem2.attrib['ANNOTATION_REF']
                                if not annot_ref in self.result:
                                    self.result[annot_ref] = []
                                self.result[annot_ref].append(elem2.attrib["ANNOTATION_ID"])

    def get_word_text(self, word):
        return list(word)[0].text

    def get_word_aid(self, word):
        return word.attrib['ANNOTATION_ID']

    def proc(self):
        for tier in self.tiers:
            tier_data = self.get_annotation_data_for_tier(tier)

            if tier_data:
                self.noref_tiers.append(tier)
        res = {}
        for aid in self.main_tier_elements:
            res[aid] = []
            if aid in self.result:
                for next_id in self.result[aid]:
                    res[aid].append(next_id)
            #else: 1st paradigm has 1 column

        perspectives = []

        ans = (
                
            sorted(
                self.eafob.get_annotation_data_for_tier(self.top_level_tier),
                key = lambda time_tup: time_tup[0])) # text

        for text_an in ans:
            next = []
            #for cur_tier in ["text", "translation", "literary translation"]:
            perspectives2 = collections.OrderedDict()
            cur_tier = "translation"
            for data in self.get_annotation_data_between_times(cur_tier, text_an[0], text_an[1]):
                time_tup = (data[0], data[1])
                translation_data = data[2]
                text_data = ""
                lit_transl_data = ""
                if res[translation_data]:
                    text_data = res[translation_data][0]
                if len(res[translation_data]) > 1:
                    lit_transl_data = res[translation_data][1]
                tr_text = hyphen_to_dash(self.word[translation_data])
                if type(tr_text) is str:
                    if re.search('[-.][\dA-Z]+', tr_text) and \
                            not re.search("[-]INF", tr_text) and \
                            not re.search("[-]SG.NOM", tr_text) and \
                            not re.search("[-]NOM", tr_text):
                        tag = re.search("[1-3][Dd][Uu]|[1-3][Pp][Ll]|[1-3][Ss][Gg]", tr_text)
                        if tag:
                            text_without_tag = tr_text.replace(tag.group(0), "")
                            if len(text_without_tag) > 0:
                                le_to_paradigms = []
                                if lit_transl_data:
                                    le_to_paradigms.append([Word(lit_transl_data ,
                                                                 self.word[lit_transl_data],
                                                                 "Word of Paradigmatic forms",
                                                                 (time_tup[0], time_tup[1])) ])
                                if text_data:
                                    le_to_paradigms.append([Word(text_data ,
                                                                 self.word[text_data], "text",
                                                                 (time_tup[0], time_tup[1])) ])
                                if translation_data:
                                    le_to_paradigms.append([Word(translation_data ,
                                                                 self.word[translation_data],
                                                                 "literary translation",
                                                                 (time_tup[0], time_tup[1])) ])
                                perspectives.append(le_to_paradigms)
                                new_list = [Word(i, self.word[i], self.word_tier[i], (time_tup[0], time_tup[1])) for i in res[translation_data]]
                                if new_list:
                                    perspectives2[Word(translation_data, self.word[translation_data], cur_tier, (time_tup[0], time_tup[1]))] = new_list
                            else:
                                new_list = [Word(i, self.word[i], self.word_tier[i], (time_tup[0], time_tup[1])) for i in res[translation_data]]
                                if new_list:
                                    perspectives2[Word(translation_data, self.word[translation_data], cur_tier, (time_tup[0], time_tup[1]))] = new_list
                        else:
                            le_to_paradigms = []
                            if lit_transl_data:
                                le_to_paradigms.append([Word(lit_transl_data ,
                                                             self.word[lit_transl_data],
                                                             "Word of Paradigmatic forms",
                                                             (time_tup[0], time_tup[1])) ])
                            if text_data:
                                le_to_paradigms.append([Word(text_data ,
                                                             self.word[text_data], "text",
                                                             (time_tup[0], time_tup[1])) ])
                            if translation_data:
                                le_to_paradigms.append([Word(translation_data ,
                                                             self.word[translation_data],
                                                             "literary translation",
                                                             (time_tup[0], time_tup[1])) ])
                            perspectives.append(le_to_paradigms)
                            new_list = [Word(i, self.word[i], self.word_tier[i], (time_tup[0], time_tup[1])) for i in res[translation_data]]
                            if new_list:
                                perspectives2[Word(translation_data, self.word[translation_data], cur_tier, (time_tup[0], time_tup[1]))] = new_list
                    else:
                        new_list = [Word(i, self.word[i], self.word_tier[i], (time_tup[0], time_tup[1])) for i in res[translation_data]]
                        if new_list:
                            perspectives2[Word(translation_data, self.word[translation_data], cur_tier, (time_tup[0], time_tup[1]))] = new_list
                else:
                    new_list = [Word(i, self.word[i], self.word_tier[i], (time_tup[0], time_tup[1])) for i in res[translation_data]]
                    if new_list:
                        perspectives2[Word(translation_data, self.word[translation_data], cur_tier, (time_tup[0], time_tup[1]))] = new_list

            if perspectives2:
                next.append(perspectives2)

            next.append([
                Word(i[2], self.word[i[2]], 'text', (i[0], i[1]))
                for i in self.get_annotation_data_between_times(self.top_level_tier, text_an[0], text_an[1])])

            cur_tier = "literary translation"
            for i in self.get_annotation_data_between_times(self.top_level_tier, text_an[0], text_an[1]):
                if i[2] in self.result:
                    for j in self.result[i[2]]:
                        if self.word_tier[j] == cur_tier:
                            next.append([Word(j, self.word[j], cur_tier, (i[0], i[1]))]) #time from text

            perspectives.append(next)

        to_fix = []
        #  Elements order fix
        for i, annotations_list in enumerate(perspectives):
            for j, obj in enumerate(annotations_list):
                if type(obj) is not list:
                    to_fix.append((i, j))
        for indexes in to_fix:
            index = indexes[0]
            wrong_obj = indexes[1]
            ordereddict = perspectives[index].pop(wrong_obj)
            perspectives[index].append(ordereddict)
        return perspectives


class ElanCheck:

    def __init__(self, eaf_path):
        self.top_tier_list = []
        self.tier_refs = collections.defaultdict(set)
        self.reader = ElementTree.parse(eaf_path)
        self.xml_obj = self.reader.getroot()
        self.edge_dict = collections.defaultdict(set)
        self.lingv_type = {}

    def parse(self):
        for element in self.xml_obj:
            if element.tag == 'TIER':
                tier_id = element.attrib['TIER_ID']
                if 'PARENT_REF' in element.attrib:
                    tier_ref = element.attrib['PARENT_REF']
                    self.edge_dict[tier_ref].add((
                        tier_id,
                        element.attrib["LINGUISTIC_TYPE_REF"]))
                    self.tier_refs[tier_ref].add(tier_id)
                else:
                    self.top_tier_list.append(tier_id)
            elif element.tag == "LINGUISTIC_TYPE":
                at = element.attrib
                if "CONSTRAINTS" in at:
                    ling_type = at["CONSTRAINTS"]
                    id = at["LINGUISTIC_TYPE_ID"]
                    is_time_alignable = at["TIME_ALIGNABLE"]
                    self.lingv_type[id] = (ling_type, is_time_alignable)

    def check(self):
        """
        Accepting EAF if we have a top-level tier with required sub-tiers.
        """

        # We certainly got to have a translation tier with two dependent transcription and word tiers.

        if ('translation' not in self.tier_refs or
            not self.tier_refs['translation'].issuperset(('transcription', 'word'))):

            return False

        tier_edge_set = set()

        for to_id, lingv_type_str in self.edge_dict['translation']:

            tier_edge_set.add((
                self.lingv_type[lingv_type_str],
                to_id))

        if not tier_edge_set.issuperset((
            (('Symbolic_Association', 'false'), 'word'),
            (('Symbolic_Association', 'false'), 'transcription'))):

            return False

        # And then we have to have a top level tier referencing two translation tiers.

        for tier_id in self.top_tier_list:

            if not self.tier_refs[tier_id].issuperset(('literary translation', 'translation')):
                continue

            tier_edge_set = set()

            for to_id, lingv_type_str in self.edge_dict[tier_id]:

                tier_edge_set.add((
                    self.lingv_type[lingv_type_str],
                    to_id))

            if tier_edge_set.issuperset((
                (('Symbolic_Association', 'false'), 'literary translation'),
                (('Included_In', 'true'), 'translation'))):

                return True

        return False

