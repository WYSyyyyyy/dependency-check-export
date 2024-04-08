import sys, os, openpyxl
from lxml import etree
from lxml.html import tostring
import requests



#leveldic = {'CRITICAL':'严重', 'HIGH':'高危', 'MEDIUM':'中危', 'LOW':'低危'}
leveldic = {'CRITICAL':'高危', 'CRITICAL*':'高危','HIGH':'高危', 'HIGH*':'高危','MEDIUM':'中危', 'LOW':'低危'}

def saveTable(vulnMaps,filename):
	if os.path.isfile(filename):
		wb = openpyxl.load_workbook(filename)
	else:
		wb = openpyxl.Workbook()
	#ws1 = wb.create_sheet(filename.split('.')[0], -1)
	# ws1 = wb.create_sheet()
	ws1 = wb.active
	ws1['A1'] = '依赖库'
	ws1['B1'] = '漏洞等级'
	ws1['C1'] = '漏洞个数'
	ws1['D1'] = '漏洞CVE'
	ws1['E1'] = '修复方案'
	#ws1['E1'] = '准确度'
	#ws1['F1'] = '特征匹配个数'
	i = 2
	for k,v in vulnMaps.items():
		if str(v[1]) != '0':
			ws1.cell(row=i, column=1).value = k
			ws1.cell(row=i, column=2).value = v[0]
			ws1.cell(row=i, column=3).value = v[1]
			ws1.cell(row=i, column=4).value = v[2]
			ws1.cell(row=i, column=5).value = v[3]
			#ws1.cell(row=i, column=5).value=k['Confidence']
			#ws1.cell(row=i, column=6).value=k['Evendence_Count']
			i+=1
	wb.save(filename)    
	wb.close()



def getjarname(s):
	if s.endswith('.jar'):
		return s
	elif s.strip().endswith(')'):
		return s[:s.index('(')].strip()
	else:
		return s[:s.index('.jar') + 4].strip()

def gethtml(fname):
	with open(fname, 'rb') as f:
		html = f.read()
		f.close()
	return html.decode()



def parsedata(html):
	alldata = []
	alldata1 = {}
	t = etree.HTML(html)
	
	jarname = t.xpath('//table[@id="summaryTable"]//tr[@class=" vulnerable"]/td[1]/a/text()')
	vulnlevel = t.xpath('//*[@id="summaryTable"]//tr[@class=" vulnerable"]/td[4]/text()')
	cvecount = t.xpath('//*[@id="summaryTable"]//tr[@class=" vulnerable"]/td[5]/text()')

	for i in range(int(len(jarname))):
	#for i in range(5):
		e1 = t.xpath('//div[@class="subsectioncontent"]')
		e2 = etree.HTML(tostring(e1[i]).decode()).xpath('//p/b/a/text()|//p/span/b/text()')
		e3 = [ee  for ee in e2 if ee.upper().startswith('CVE')]
		# tmpdata = [getjarname(jarname[i]), leveldic.get(vulnlevel[i].upper()), cvecount[i], ','.join(e2)]

		# print(e3)
		#对CVE进行排序
		e4 = sort_cve(e3)
		# print(e4)
		if len(e4) > 0:
			cve_id = e4[-1]
		cve_solution = get_solution(cve_id)
		# print("修复方案：")
		# print(cve_solution)

		realjarname = getjarname(jarname[i])
		#tmpdata1 = {realjarname: [leveldic.get(vulnlevel[i].upper()), cvecount[i], ','.join(e3)]}
		tmpdata1 = {realjarname: [leveldic.get(vulnlevel[i].upper()), str(len(e3)), ','.join(e4), cve_solution]}		#无cve号
		# print("tmpdata1")
		# print(tmpdata1)
		# alldata.append(tmpdata)
		if not realjarname in alldata1:
			alldata1.update(tmpdata1)
		
		if str(cvecount[i]) != str(len(e3)):
			print('警告：cve编号个数不对，请检查报告里面是否没有相关cve编号','jar名:{},报告cve个数:{},实际获取cve编号个数:{}'.format(jarname[i], cvecount[i], len(e3)))
		
		# if i == 1:
		# 	break
		
	'''
	with open('dependency-check-report.txt', 'w') as f:
		for k, v in alldata1.items():
			f.write('\t'.join([k, '\t'.join(v)]))
			f.write('\n')
		f.close()
	'''
	return alldata1

#对CVE进行排序
def sort_cve(cve_list):

	def cve_key(cve):
		parts = cve.split('-')
		#按照年份和编号进行排序，优先年份
		return int(parts[1]), int(parts[2])
	
	cve_list.sort(key=cve_key)
	return cve_list

#获取修复方案
def get_solution(cve_id):
	#使用阿里云的漏洞库，需要将cve-xxxx-xxxxx 替换为 AVD-xxxx-xxxxx
	avd_id = cve_id.replace('CVE', 'AVD')
	url = "https://avd.aliyun.com/detail?id="+str(avd_id)
	response = requests.get(url)
	if response.status_code == 200:
		html = response.text
		t = etree.HTML(html)
		#找到div里面的解决建议
		e1 = t.xpath('//*[@class="py-4 pl-4 pr-4 px-2 bg-white rounded shadow-sm"]/div[2]/text()')
		# e1 = t.xpath('/html/body/div[3]/div/div[1]/div[2]/div[2]/text()')
		if len(e1) > 0:
		#e1是str，去除空格和换行
			return e1[0].replace('\n', '').replace('\t', '').strip()
	else:
		return "升级至最新版本。"


if __name__ == '__main__':
	htmlreportname = 'dependency-check-report.html'
	htmlreportname = sys.argv[-1]
	html = gethtml(htmlreportname)
	datadic = parsedata(html)
	saveTable(datadic, htmlreportname.split('.')[0] + '.xlsx')
	print('ok')

