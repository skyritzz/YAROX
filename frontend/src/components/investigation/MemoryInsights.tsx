import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { api } from '@/lib/api';

interface SimilarityResult {
  investigation_id: string;
  similarity_score: number;
  semantic_score: number;
  mitre_overlap_score: number;
  ioc_overlap_score: number;
  attack_type_match: boolean;
  campaign_match: boolean;
  created_at?: string;
  knowledge_object: {
    investigation: { title: string; summary: string };
    attack: { attack_type: string; campaign: string; mitre_techniques: string[] };
  };
}

export const MemoryInsights: React.FC<{ caseId: string }> = ({ caseId }) => {
  const [similarCases, setSimilarCases] = useState<SimilarityResult[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get(`/investigations/${caseId}/similar`)
      .then(res => {
        const data = res.data;
        if (Array.isArray(data)) {
          setSimilarCases(data);
        } else {
          console.warn('API returned non-array for similar cases:', data);
          setSimilarCases([]);
        }
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, [caseId]);

  const uniqueCases = similarCases.filter((sim, index, self) =>
    index === self.findIndex((t) => (
      t.knowledge_object?.investigation?.title === sim.knowledge_object?.investigation?.title &&
      t.knowledge_object?.investigation?.summary === sim.knowledge_object?.investigation?.summary
    ))
  );

  if (loading) return <div className="text-sm text-[var(--text-secondary)] p-4">Loading memory insights...</div>;
  if (!uniqueCases.length) return <div className="text-sm text-[var(--text-secondary)] py-4">No historical similarities found.</div>;

  return (
    <div
      className="bg-gradient-to-br from-blue-50/50 to-white rounded-2xl p-5 mb-6"
      style={{
        boxShadow: "var(--shadow-card)",
        border: "1px solid var(--border-default)",
      }}
    >
      <div className="flex justify-between items-center mb-4">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-blue-100 flex items-center justify-center text-blue-600">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h3 className="text-sm font-bold text-gray-900">
            Historical Intelligence Matches
          </h3>
        </div>
      </div>
      
      <div className="space-y-3">
        {uniqueCases.map((sim, i) => (
          <div key={i} className="group bg-white rounded-xl p-4 border border-blue-100 border-l-4 border-l-blue-500 hover:shadow-md transition-all relative overflow-hidden">
            <div className="flex justify-between items-start mb-1.5">
              <div className="flex items-center gap-3">
                <span className="bg-blue-100 text-blue-700 text-[10px] font-bold px-2.5 py-0.5 rounded-full uppercase tracking-wider">
                  {(sim.similarity_score * 100).toFixed(0)}% Match
                </span>
                {sim.created_at && (
                  <span className="flex items-center gap-1 text-[11px] text-gray-500 font-medium">
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                    {new Date(sim.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                  </span>
                )}
              </div>
              <Link 
                href={`/investigations/${sim.investigation_id}`} 
                className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800 bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-lg transition-colors"
              >
                View Case
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
              </Link>
            </div>
            
            <h4 className="font-bold text-sm text-gray-900 mb-1">
              {sim.knowledge_object?.investigation?.title || `Historical Incident: ${sim.investigation_id.substring(0, 8)}`}
            </h4>
            
            <p className="text-xs text-gray-600 mb-3 line-clamp-2 leading-relaxed">
              {sim.knowledge_object?.investigation?.summary}
            </p>
            
            <div className="flex flex-wrap gap-2 text-[10px] font-semibold tracking-wide">
              {sim.attack_type_match && <span className="bg-red-50 text-red-600 border border-red-100 px-2 py-0.5 rounded-md">Attack Type Match</span>}
              {sim.campaign_match && <span className="bg-purple-50 text-purple-600 border border-purple-100 px-2 py-0.5 rounded-md">Campaign Match</span>}
              {sim.mitre_overlap_score > 0 && <span className="bg-green-50 text-green-600 border border-green-100 px-2 py-0.5 rounded-md">MITRE Overlap</span>}
              {sim.ioc_overlap_score > 0 && <span className="bg-yellow-50 text-yellow-600 border border-yellow-100 px-2 py-0.5 rounded-md">Shared IOCs</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
